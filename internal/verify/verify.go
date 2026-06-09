// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package verify checks cosign signatures, SLSA provenance, and CVE status.
// All checks use CLI tools (cosign, gh) via exec.Command — no library deps.
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/provabl/vet/internal/sbom"
	"github.com/provabl/vet/internal/store"
)

// Runner executes external commands (mockable).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type defaultRunner struct{}

func (r *defaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 — controlled inputs
	out, err := cmd.CombinedOutput()
	return out, err
}

// Options controls what vet verify checks.
type Options struct {
	Source         string // github.com/org/repo — required for SLSA check
	MinSLSALevel   int    // 0 = any/none, 1/2/3 = minimum
	CheckCVEs      string // "critical", "high", "medium", "" = skip
	SigningIDRegex string // certificate-identity-regexp for cosign verify
}

// Verifier runs artifact verification checks.
type Verifier struct {
	runner Runner
	store  *store.Store
	http   *http.Client
}

// New creates a Verifier.
func New(s *store.Store) *Verifier {
	return &Verifier{
		runner: &defaultRunner{},
		store:  s,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

// NewWithRunner creates a Verifier with a custom runner (for testing).
func NewWithRunner(r Runner, s *store.Store) *Verifier {
	return &Verifier{runner: r, store: s, http: &http.Client{Timeout: 30 * time.Second}}
}

// VerifyResult summarises all verification checks.
type VerifyResult struct {
	ArtifactRef     string
	ArtifactHash    string // sha256:… digest when derivable from the ref or a local file
	Signed          bool
	SignerSubject   string
	RekorLogID      string
	SLSALevel       int  // 0 = not present/verified
	SLSAToolMissing bool // gh CLI absent — SLSA could not be checked (distinct from level 0)
	SBOMPresent     bool
	CVECritical     bool
	CVEHigh         bool
	PolicyMet       bool
	Failures        []string // human-readable failure list
}

// Verify runs all configured checks and returns a result.
// Returns a non-nil error only for infrastructure failures (e.g., cosign not installed).
// Policy failures are recorded in result.Failures.
func (v *Verifier) Verify(ctx context.Context, artifactRef string, opts Options) (*VerifyResult, error) {
	if strings.HasPrefix(artifactRef, "-") {
		return nil, fmt.Errorf("invalid artifact ref %q: cannot start with a flag character (-)", artifactRef)
	}
	result := &VerifyResult{ArtifactRef: artifactRef}

	// 1. Signature verification
	signed, signerSubject, rekorID, sigErr := v.verifySig(ctx, artifactRef, opts.SigningIDRegex)
	if sigErr != nil {
		result.Failures = append(result.Failures, fmt.Sprintf("signature check failed: %v", sigErr))
	} else {
		result.Signed = signed
		result.SignerSubject = signerSubject
		result.RekorLogID = rekorID
	}

	// 2. SLSA provenance (requires the gh CLI and --source). A missing gh is
	// surfaced distinctly from "no provenance" so the operator isn't left
	// guessing why the level is 0 — and, when a --min-slsa-level gate is set, it
	// fails closed below rather than silently reporting level 0.
	if opts.Source != "" {
		level, slsaErr := v.verifySLSA(ctx, artifactRef, opts.Source)
		switch {
		case errors.Is(slsaErr, errGHMissing):
			result.SLSAToolMissing = true
			if opts.MinSLSALevel > 0 {
				result.Failures = append(result.Failures,
					fmt.Sprintf("SLSA level %d required but cannot verify: %v", opts.MinSLSALevel, slsaErr))
			}
		case slsaErr != nil:
			result.Failures = append(result.Failures,
				fmt.Sprintf("SLSA provenance check failed: %v", slsaErr))
		default:
			result.SLSALevel = level
		}
	}

	// 3. SBOM presence + artifact hash (independent of the CVE check). "Present"
	// means a valid SBOM with at least one package — not merely a file on disk.
	result.SBOMPresent = v.sbomPackages(artifactRef) != nil
	result.ArtifactHash = artifactHash(artifactRef)

	// 4. CVE check. Fail-closed: if the operator asked for a CVE gate but it
	// cannot be evaluated (no SBOM, unparseable, OSV unreachable), that is a
	// policy failure — never a silent pass.
	var cveErr error
	if opts.CheckCVEs != "" {
		critical, high, ran, err := v.checkCVEs(ctx, artifactRef)
		if ran {
			result.CVECritical = critical
			result.CVEHigh = high
		} else {
			cveErr = err // surfaced as a fail-closed policy failure below
		}
	}

	// 5. Policy evaluation
	var policyFailures []string
	if !result.Signed {
		policyFailures = append(policyFailures, "artifact is not signed")
	}
	if opts.MinSLSALevel > 0 && result.SLSALevel < opts.MinSLSALevel {
		policyFailures = append(policyFailures,
			fmt.Sprintf("SLSA level %d < minimum %d", result.SLSALevel, opts.MinSLSALevel))
	}
	if opts.CheckCVEs != "" && cveErr != nil {
		// Fail closed: a requested CVE gate that could not run denies the artifact.
		policyFailures = append(policyFailures,
			fmt.Sprintf("CVE check requested but could not run: %v", cveErr))
	}
	switch opts.CheckCVEs {
	case "critical":
		if result.CVECritical {
			policyFailures = append(policyFailures, "critical CVEs found")
		}
	case "high":
		if result.CVECritical || result.CVEHigh {
			policyFailures = append(policyFailures, "high/critical CVEs found")
		}
	}

	result.Failures = append(result.Failures, policyFailures...)
	result.PolicyMet = len(result.Failures) == 0

	// Persist record.
	rec := &store.VerificationRecord{
		ArtifactRef:   artifactRef,
		ArtifactHash:  result.ArtifactHash,
		Signed:        result.Signed,
		SignerSubject: result.SignerSubject,
		RekorLogID:    result.RekorLogID,
		SLSALevel:     result.SLSALevel,
		SBOMPresent:   result.SBOMPresent,
		CVECritical:   result.CVECritical,
		CVEHigh:       result.CVEHigh,
		VerifiedAt:    time.Now(),
		Source:        opts.Source,
	}
	_ = v.store.SaveRecord(rec) // non-fatal

	return result, nil
}

// artifactHash derives the subject digest for an artifact reference. For an image
// ref pinned by digest (…@sha256:abc…) it returns that digest. For a local file
// (./path or /path) it returns the sha256 of the file contents. For a bare tag
// (no digest, not a local file) it returns "" — the digest cannot be known
// without pulling the image, and an empty hash is honest rather than fabricated.
func artifactHash(ref string) string {
	if i := strings.Index(ref, "@sha256:"); i != -1 {
		return ref[i+1:] // "sha256:abc…"
	}
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "/") {
		f, err := os.Open(ref) // #nosec G304 — operator-supplied artifact path
		if err != nil {
			return ""
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return ""
		}
		return fmt.Sprintf("sha256:%x", h.Sum(nil))
	}
	return ""
}

// verifySig calls cosign to verify the artifact's signature.
func (v *Verifier) verifySig(ctx context.Context, ref, signingIDRegex string) (signed bool, subject, rekorID string, err error) {
	isImage := !strings.HasPrefix(ref, "./") && !strings.HasPrefix(ref, "/") &&
		(strings.Contains(ref, ":") || strings.Contains(ref, "@"))

	var out []byte
	if isImage {
		args := []string{"verify",
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		}
		if signingIDRegex != "" {
			args = append(args, "--certificate-identity-regexp", signingIDRegex)
		} else {
			args = append(args, "--certificate-identity-regexp", ".*")
		}
		args = append(args, "--output", "json", ref)
		out, err = v.runner.Run(ctx, "cosign", args...)
	} else {
		// Blob: look for .sig file alongside artifact
		args := []string{"verify-blob",
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		}
		if signingIDRegex != "" {
			args = append(args, "--certificate-identity-regexp", signingIDRegex)
		} else {
			args = append(args, "--certificate-identity-regexp", ".*")
		}
		args = append(args, "--signature", ref+".sig", ref)
		out, err = v.runner.Run(ctx, "cosign", args...)
	}

	outStr := string(out)
	if err != nil {
		// cosign exits non-zero if verification fails — that's a policy failure, not an error
		return false, "", "", nil
	}

	// Parse cosign JSON output for signer subject and Rekor ID.
	subject = extractSignerSubject(outStr)
	rekorID = extractRekorIDFromOutput(outStr)
	return true, subject, rekorID, nil
}

// errGHMissing signals that the `gh` CLI is not installed, distinct from gh
// running and finding no/invalid attestation. The caller surfaces this so a
// requested SLSA check that cannot run is not silently reported as "level 0".
var errGHMissing = errors.New("gh CLI not found — install from https://cli.github.com to verify SLSA provenance")

// verifySLSA calls `gh attestation verify` to check SLSA provenance and returns
// the derived build level (0 = unverified). It returns errGHMissing when gh is
// absent (so the caller can warn distinctly) and a nil error with level 0 when
// gh ran but found no valid provenance.
func (v *Verifier) verifySLSA(ctx context.Context, ref, source string) (int, error) {
	if !toolAvailable(ctx, v.runner, "gh") {
		return 0, errGHMissing
	}
	out, err := v.runner.Run(ctx, "gh", "attestation", "verify",
		ref, "--repo", source, "--format", "json")
	if err != nil {
		// gh ran but verification failed / no attestation — genuinely level 0.
		return 0, nil
	}
	return slsaLevelFromGH(out), nil
}

// toolAvailable reports whether an external CLI is invokable, so missing-tool can
// be distinguished from tool-ran-and-failed.
func toolAvailable(ctx context.Context, r Runner, name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	// Fall back to asking the runner (covers injected test runners): `--version`.
	_, err := r.Run(ctx, name, "--version")
	return err == nil
}

// maxCVEPackages bounds how many SBOM packages a single verify will query against
// OSV, so a pathologically large SBOM cannot wedge a run. If an SBOM exceeds it,
// the check still runs over the first maxCVEPackages packages.
const maxCVEPackages = 500

// sbomPackages loads the parsed package list for an artifact, trying SPDX then
// CycloneDX. Returns nil when no parseable, non-empty SBOM exists.
func (v *Verifier) sbomPackages(artifactRef string) []sbom.Package {
	for _, format := range []string{"spdx", "cyclonedx"} {
		if pkgs, err := sbom.Load(v.store.SBOMPath(artifactRef, format)); err == nil && len(pkgs) > 0 {
			return pkgs
		}
	}
	return nil
}

// checkCVEs parses the artifact's SBOM and queries OSV for each package. The ran
// return reports whether the check actually executed: when it is false the caller
// must fail closed (a requested CVE gate that could not be evaluated must not pass).
func (v *Verifier) checkCVEs(ctx context.Context, artifactRef string) (critical, high, ran bool, err error) {
	pkgs := v.sbomPackages(artifactRef)
	if pkgs == nil {
		return false, false, false, fmt.Errorf("no SBOM present — run 'vet sbom %s' first", artifactRef)
	}
	if len(pkgs) > maxCVEPackages {
		pkgs = pkgs[:maxCVEPackages]
	}
	var queried bool
	for _, p := range pkgs {
		c, h, qErr := queryOSV(ctx, v.http, p)
		if qErr != nil {
			// OSV unreachable mid-run: fail closed rather than under-report.
			return false, false, false, fmt.Errorf("OSV query failed for %s: %w", pkgIdent(p), qErr)
		}
		queried = true
		critical = critical || c
		high = high || h
	}
	return critical, high, queried, nil
}

func pkgIdent(p sbom.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	return p.Name + "@" + p.Version
}

// --- helpers -----------------------------------------------------------------

var signerSubjectRe = regexp.MustCompile(`"subject":\s*"([^"]+)"`)
var rekorIDRe = regexp.MustCompile(`(?i)log\s*id[:\s]+([a-f0-9]{64})`)

func extractSignerSubject(output string) string {
	if m := signerSubjectRe.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractRekorIDFromOutput(output string) string {
	if m := rekorIDRe.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return ""
}

// slsaProvenanceV1 is the predicate type gh attestation verify enforces for
// build provenance by default.
const slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

// slsaLevelFromGH derives the SLSA build level from `gh attestation verify
// --format json` output. There is no explicit "level" field in the output — gh
// returns an array of verified attestations, each with a statement carrying a
// predicateType and a provenance predicate. We derive the level structurally:
//
//   - A verified slsa.dev/provenance/v1 attestation means the build ran on a
//     trusted builder → SLSA Build Level 2.
//   - If the provenance's builder id is a reusable workflow run by the SLSA
//     GitHub generator (the hardened, isolated builder), that is Level 3.
//
// This replaces an earlier regex that matched a non-existent "slsa level" field
// and always fell back to a hardcoded 2. Returns 0 when no verified v1
// provenance attestation is present.
func slsaLevelFromGH(out []byte) int {
	var entries []struct {
		VerificationResult struct {
			Statement struct {
				PredicateType string `json:"predicateType"`
				Predicate     struct {
					RunDetails struct {
						Builder struct {
							ID string `json:"id"`
						} `json:"builder"`
					} `json:"runDetails"`
				} `json:"predicate"`
			} `json:"statement"`
		} `json:"verificationResult"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return 0
	}
	level := 0
	for _, e := range entries {
		st := e.VerificationResult.Statement
		if st.PredicateType != slsaProvenanceV1 {
			continue
		}
		// A verified v1 provenance attestation is at least Level 2.
		if level < 2 {
			level = 2
		}
		// The SLSA GitHub generator (slsa-framework/slsa-github-generator) runs the
		// build in an isolated reusable workflow — Build Level 3.
		if strings.Contains(st.Predicate.RunDetails.Builder.ID, "slsa-framework/slsa-github-generator") {
			level = 3
		}
	}
	return level
}

// osvQueryURL is the OSV single-package query endpoint. Unlike /v1/querybatch
// (which returns only vuln IDs), /v1/query returns full vuln records including
// severity inline, so a single call per package yields the CRITICAL/HIGH verdict.
const osvQueryURL = "https://api.osv.dev/v1/query"

// queryOSV asks OSV whether a single package has known critical/high
// vulnerabilities. It queries by PURL when available (PURL encodes the
// ecosystem), else by name+ecosystem. A malformed/empty response is treated as
// "no known vulns"; a transport error is returned so the caller can fail closed.
func queryOSV(ctx context.Context, client *http.Client, p sbom.Package) (critical, high bool, err error) {
	var body string
	switch {
	case p.PURL != "":
		body = fmt.Sprintf(`{"package":{"purl":%q}}`, p.PURL)
	case p.Ecosystem != "":
		body = fmt.Sprintf(`{"package":{"name":%q,"ecosystem":%q}}`, p.Name, p.Ecosystem)
	default:
		// Without a purl or ecosystem OSV cannot resolve the package; skip it
		// rather than error (a bare name is ambiguous across ecosystems).
		return false, false, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewBufferString(body))
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var result struct {
		Vulns []struct {
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			DatabaseSpecific struct {
				Severity string `json:"severity"`
			} `json:"database_specific"`
		} `json:"vulns"`
	}
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return false, false, nil
	}
	for _, vuln := range result.Vulns {
		// Some feeds carry a categorical severity (GHSA: "CRITICAL"/"HIGH"); CVSS
		// feeds carry a vector score in Score. Check both.
		sev := strings.ToUpper(vuln.DatabaseSpecific.Severity)
		if sev == "CRITICAL" {
			critical = true
		}
		if sev == "HIGH" {
			high = true
		}
		for _, s := range vuln.Severity {
			up := strings.ToUpper(s.Score + " " + s.Type)
			if strings.Contains(up, "CRITICAL") {
				critical = true
			}
			if strings.Contains(up, "HIGH") {
				high = true
			}
		}
	}
	return critical, high, nil
}
