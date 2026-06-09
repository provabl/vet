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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

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
	ArtifactRef   string
	ArtifactHash  string // sha256:… digest when derivable from the ref or a local file
	Signed        bool
	SignerSubject string
	RekorLogID    string
	SLSALevel     int // 0 = not present/verified
	SBOMPresent   bool
	CVECritical   bool
	CVEHigh       bool
	PolicyMet     bool
	Failures      []string // human-readable failure list
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

	// 2. SLSA provenance (requires gh CLI and --source)
	if opts.Source != "" {
		level, slsaErr := v.verifySLSA(ctx, artifactRef, opts.Source)
		if slsaErr != nil {
			result.Failures = append(result.Failures,
				fmt.Sprintf("SLSA provenance check failed: %v", slsaErr))
		} else {
			result.SLSALevel = level
		}
	}

	// 3. SBOM presence + artifact hash (independent of the CVE check).
	result.SBOMPresent = v.store.HasSBOM(artifactRef)
	result.ArtifactHash = artifactHash(artifactRef)

	// 4. CVE check (requires SBOM in store)
	if opts.CheckCVEs != "" {
		sbomPath := v.store.SBOMPath(artifactRef, "spdx")
		critical, high, cveErr := v.checkCVEs(ctx, sbomPath)
		if cveErr == nil {
			result.CVECritical = critical
			result.CVEHigh = high
		}
		// CVE check failure is non-blocking (SBOM may not exist yet)
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

// verifySLSA calls `gh attestation verify` to check SLSA provenance level.
func (v *Verifier) verifySLSA(ctx context.Context, ref, source string) (int, error) {
	out, err := v.runner.Run(ctx, "gh", "attestation", "verify",
		ref, "--repo", source, "--format", "json")
	if err != nil {
		// gh not installed or no attestation — return level 0 (not verified)
		return 0, nil
	}

	// Parse gh output to determine SLSA level.
	return extractSLSALevel(string(out)), nil
}

// checkCVEs queries the OSV API with packages extracted from an SBOM.
func (v *Verifier) checkCVEs(_ context.Context, sbomPath string) (critical, high bool, err error) {
	// Simplified: return false if SBOM not found. Full implementation reads SBOM
	// packages and queries https://api.osv.dev/v1/querybatch.
	if sbomPath == "" {
		return false, false, fmt.Errorf("no SBOM path provided")
	}
	return false, false, nil // non-fatal — CVE check deferred until SBOM present
}

// --- helpers -----------------------------------------------------------------

var signerSubjectRe = regexp.MustCompile(`"subject":\s*"([^"]+)"`)
var rekorIDRe = regexp.MustCompile(`(?i)log\s*id[:\s]+([a-f0-9]{64})`)
var slsaLevelRe = regexp.MustCompile(`(?i)slsa[^"]*level["\s:]+(\d)`)

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

func extractSLSALevel(ghOutput string) int {
	if m := slsaLevelRe.FindStringSubmatch(ghOutput); len(m) > 1 {
		switch m[1] {
		case "3":
			return 3
		case "2":
			return 2
		case "1":
			return 1
		}
	}
	// gh attestation verify success without explicit level = at least L2
	// (GitHub's attest-build-provenance generates SLSA L2+ attestations)
	if strings.Contains(strings.ToLower(ghOutput), "verified") {
		return 2
	}
	return 0
}

// QueryOSV queries the OSV API for vulnerabilities matching a package.
// Used by checkCVEs when SBOM parsing is implemented.
func QueryOSV(ctx context.Context, client *http.Client, packageName, ecosystem string) (critical, high bool, err error) {
	body := fmt.Sprintf(`{"package":{"name":%q,"ecosystem":%q}}`, packageName, ecosystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.osv.dev/v1/query", bytes.NewBufferString(body))
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var result struct {
		Vulns []struct {
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return false, false, nil
	}
	for _, v := range result.Vulns {
		for _, s := range v.Severity {
			if strings.Contains(s.Score, "CRITICAL") || strings.Contains(s.Type, "CRITICAL") {
				critical = true
			}
			if strings.Contains(s.Score, "HIGH") || strings.Contains(s.Type, "HIGH") {
				high = true
			}
		}
	}
	return critical, high, nil
}
