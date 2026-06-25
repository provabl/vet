// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/provabl/vet/internal/amiscan"
	"github.com/provabl/vet/internal/amitag"
	"github.com/provabl/vet/internal/cve"
	"github.com/provabl/vet/internal/gate"
	"github.com/provabl/vet/internal/preflight"
	"github.com/provabl/vet/internal/sbom"
	"github.com/provabl/vet/internal/sign"
	"github.com/provabl/vet/internal/store"
	"github.com/provabl/vet/internal/verify"
)

var version = "0.2.0"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vet",
		Short: "Software supply chain verification for AWS Secure Research Environments",
		Long: `vet verifies software artifacts before they access sensitive data in an SRE.
Where qualify qualifies the person, vet qualifies the software.

  vet sign    image:tag            # sign via Sigstore keyless
  vet verify  image:tag            # verify SLSA provenance + CVE status
  vet sbom    image:tag --attest   # generate and attest SBOM
  vet gate    image:tag            # write Cedar workload attributes for attest`,
		Version: version,
	}
	cmd.AddCommand(signCmd(), verifyCmd(), sbomCmd(), gateCmd(), amiReferenceCmd(), amiScanCmd(), preflightCmd())
	return cmd
}

// preflightCmd verifies the calling principal holds the IAM actions vet needs.
func preflightCmd() *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Verify the calling principal holds the IAM permissions vet needs",
		Long: `Check that the calling AWS principal can perform vet's AWS-touching actions
(the AMI vetter's ec2:CreateTags), via read-only iam:SimulatePrincipalPolicy
against the caller — it evaluates, it does not act. A denied action prints a
remediation and the command exits non-zero. See docs/required-permissions.md.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPreflight(preflight.CheckCallerPermissions(cmd.Context(), region))
		},
	}
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")
	return cmd
}

// runPreflight renders preflight results and returns a non-nil error if any failed.
func runPreflight(results []preflight.Result) error {
	failures := 0
	for _, r := range results {
		if r.Status {
			fmt.Printf("  ✓ %s\n", r.Name)
			continue
		}
		failures++
		fmt.Printf("  ✗ %s: %s\n", r.Name, r.Detail)
		if r.Remediation != "" {
			fmt.Printf("      Remediation: %s\n", r.Remediation)
		}
	}
	fmt.Println()
	if failures > 0 {
		return fmt.Errorf("preflight failed: %d required permission(s) missing", failures)
	}
	fmt.Println("✓ All required permissions present")
	return nil
}

// ── sign ──────────────────────────────────────────────────────────────────────

func signCmd() *cobra.Command {
	var yes bool
	var vetDir string

	cmd := &cobra.Command{
		Use:   "sign <artifact>",
		Short: "Sign an artifact using Sigstore keyless signing",
		Long: `Sign a container image or local binary using cosign keyless signing.
No private key needed — identity comes from GitHub Actions OIDC (in CI)
or browser-based OIDC for interactive use. Signature is written to the
Rekor transparency log.

Examples:
  vet sign ghcr.io/org/image:v1.0
  vet sign ./pipeline-binary
  vet sign s3://bucket/model.tar.gz --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(args[0], vetDir, yes)
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip interactive confirmation")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	return cmd
}

func runSign(artifactRef, vetDir string, yes bool) error {
	s := store.New(vetDir)
	signer := sign.New(s, yes)

	fmt.Printf("Signing %s...\n", artifactRef)
	result, err := signer.Sign(contextWithTimeout(), artifactRef)
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	fmt.Printf("✓ Signed via Sigstore keyless\n")
	if result.RekorLogID != "" {
		fmt.Printf("  Rekor log entry: %s\n", result.RekorLogID)
	}
	fmt.Printf("  Record: %s/records/\n", vetDir)
	return nil
}

// ── verify ────────────────────────────────────────────────────────────────────

func verifyCmd() *cobra.Command {
	var source string
	var minSLSA int
	var checkCVEs string
	var signingID string
	var vetDir string
	var cveSource string

	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify SLSA provenance and CVE status of an artifact",
		Long: `Verify a container image or binary against configured policy.
Checks: cosign signature, SLSA provenance, CVE status.

Required external tools (per check):
  --source         the GitHub CLI 'gh' (SLSA provenance via 'gh attestation verify')
  signature        cosign
  --check-cves     a stored SBOM ('vet sbom <artifact>'); CVEs are queried from OSV

If a requested check's tool or input is missing, verify fails closed (it does not
silently pass): a missing 'gh' with --min-slsa-level, or --check-cves with no SBOM,
is reported as a policy violation rather than assumed clean.

Exit codes: 0 = verified, 1 = policy violation, 2 = error

Examples:
  vet verify ghcr.io/org/image:v1.0 --source github.com/org/repo --min-slsa-level 2
  vet verify ghcr.io/org/image:v1.0 --check-cves critical
  vet verify ./binary --source github.com/org/repo`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := resolveCVESource(cveSource, args[0])
			if err != nil {
				return err
			}
			return runVerify(args[0], vetDir, src, verify.Options{
				Source:         source,
				MinSLSALevel:   minSLSA,
				CheckCVEs:      checkCVEs,
				SigningIDRegex: signingID,
			})
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "GitHub repo (e.g. github.com/org/repo) for SLSA verification")
	cmd.Flags().IntVar(&minSLSA, "min-slsa-level", 0, "minimum SLSA level required (0 = any)")
	cmd.Flags().StringVar(&checkCVEs, "check-cves", "", "fail on CVEs at or above: critical, high, medium")
	cmd.Flags().StringVar(&signingID, "signing-id-regexp", "", "certificate-identity-regexp for cosign")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	cmd.Flags().StringVar(&cveSource, "cve-source", "auto",
		"CVE scanner: auto (grype for AMIs, osv otherwise), osv, or grype (distro-aware, needs the grype binary)")
	return cmd
}

// amiScanCmd runs deep AMI content scanning: it resolves the AMI's backing EBS
// snapshot, materialises its filesystem on an operator-provided helper instance,
// syfts it, and stores the SBOM where `vet verify ami-… --check-cves` (which
// auto-routes AMIs to the distro-aware grype source) then reads it. This is the
// live half of provabl/vet#32 — it creates a volume + attachment (never an
// instance, never the AMI's own snapshot) and tears them down when done.
func amiScanCmd() *cobra.Command {
	var region, helperInstance, az, device, bucket, vetDir string
	cmd := &cobra.Command{
		Use:   "ami-scan <ami-id>",
		Short: "Deep-scan an AMI's contents (snapshot → syft) into a stored SBOM",
		Long: `Resolve the AMI's backing EBS snapshot, mount a copy of it read-only on a
helper instance, run syft over its filesystem, and store the resulting SBOM so
'vet verify <ami-id> --check-cves <level>' can gate on it (AMIs auto-route to the
distro-aware grype scanner).

vet creates a volume from the snapshot and attaches it to the helper, then
detaches and deletes that volume when done — it never creates/terminates the
helper instance and never touches the AMI's own snapshot.

Prerequisites (operator-provided):
  --helper-instance  a running, SSM-managed, syft- + awscli-equipped EC2 instance
  --az               the helper's availability zone (the scan volume must match)
  --scan-bucket      an S3 bucket the helper can PutObject and you can GetObject

Example:
  vet ami-scan ami-0abc --helper-instance i-0helper --az us-east-1a \
      --scan-bucket my-vet-staging
  vet verify ami-0abc --check-cves high`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amiID := args[0]
			if !isAMIRef(amiID) {
				return fmt.Errorf("expected an AMI id (ami-...), got %q", amiID)
			}
			if helperInstance == "" || az == "" || bucket == "" {
				return fmt.Errorf("--helper-instance, --az, and --scan-bucket are required")
			}
			return runAMIScan(cmd.Context(), amiID, region, vetDir, bucket,
				amiscan.Config{InstanceID: helperInstance, AZ: az, Device: device})
		},
	}
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")
	cmd.Flags().StringVar(&helperInstance, "helper-instance", "", "running SSM-managed, syft-equipped helper EC2 instance (required)")
	cmd.Flags().StringVar(&az, "az", "", "the helper instance's availability zone (required)")
	cmd.Flags().StringVar(&device, "device", "/dev/sdf", "device name to attach the scan volume at")
	cmd.Flags().StringVar(&bucket, "scan-bucket", "", "S3 bucket for the SBOM hand-off (required)")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	return cmd
}

// runAMIScan drives the amiscan pipeline and copies the produced SBOM into the
// store at the AMI's CycloneDX path, so the existing verify/gate CVE path finds it.
func runAMIScan(ctx context.Context, amiID, region, vetDir, bucket string, cfg amiscan.Config) error {
	s := store.New(vetDir)
	if err := s.Init(); err != nil {
		return err
	}
	scanner, err := amiscan.NewLive(ctx, region, bucket, vetDir, cfg)
	if err != nil {
		return err
	}

	fmt.Printf("Deep-scanning %s (snapshot → syft on %s)...\n", amiID, cfg.InstanceID)
	sbomPath, release, err := scanner.Scan(ctx, amiID)
	if release != nil {
		defer func() {
			if rerr := release(ctx); rerr != nil {
				fmt.Fprintf(os.Stderr, "warning: scan-volume teardown: %v\n", rerr)
			}
		}()
	}
	if err != nil {
		return fmt.Errorf("ami content scan: %w", err)
	}

	dest := s.SBOMPath(amiID, "cyclonedx")
	if err := copyFile(sbomPath, dest); err != nil {
		return fmt.Errorf("store SBOM: %w", err)
	}
	fmt.Printf("✓ SBOM stored at %s\n", dest)
	fmt.Printf("  Next: vet verify %s --check-cves high   (auto-routes to grype)\n", amiID)
	return nil
}

// copyFile copies src to dst (the store's SBOM path).
func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 — scanner-produced path
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) // #nosec G304 — store-derived path
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// resolveCVESource picks the CVE scanner. "auto" routes AMI targets to grype
// (distro-advisory aware — a naive OSV query is false-clean on a distro AMI,
// provabl/vet#32) and everything else to OSV; an explicit name overrides.
func resolveCVESource(name, artifactRef string) (cve.Source, error) {
	switch name {
	case "osv":
		return cve.NewOSVSource(nil), nil
	case "grype":
		return cve.NewGrypeSource(), nil
	case "auto", "":
		if isAMIRef(artifactRef) {
			return cve.NewGrypeSource(), nil
		}
		return cve.NewOSVSource(nil), nil
	default:
		return nil, fmt.Errorf("unknown --cve-source %q (want: auto, osv, grype)", name)
	}
}

func runVerify(artifactRef, vetDir string, cveSrc cve.Source, opts verify.Options) error {
	s := store.New(vetDir)
	v := verify.New(s).WithCVESource(cveSrc)

	fmt.Printf("Verifying %s...\n", artifactRef)
	result, err := v.Verify(contextWithTimeout(), artifactRef, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if result.Signed {
		fmt.Printf("  ✓ Signed")
		if result.SignerSubject != "" {
			fmt.Printf(" — %s", result.SignerSubject)
		}
		fmt.Println()
	} else {
		fmt.Println("  ✗ Not signed or signature invalid")
	}

	if opts.Source != "" {
		switch {
		case result.SLSAToolMissing:
			fmt.Println("  ✗ SLSA provenance not checked — gh CLI not installed (https://cli.github.com)")
		case result.SLSALevel > 0:
			fmt.Printf("  ✓ SLSA Level %d provenance verified\n", result.SLSALevel)
		default:
			fmt.Println("  ✗ SLSA provenance not found or unverified")
		}
	}

	if opts.CheckCVEs != "" {
		switch {
		case result.CVECritical:
			fmt.Println("  ✗ Critical CVEs found")
			if result.CVEHigh {
				fmt.Println("  ✗ High CVEs found")
			}
		case result.CVEHigh:
			fmt.Println("  ✗ High CVEs found")
		case !result.CVECheckRan:
			// The CVE gate could not run (no SBOM, scanner missing, DB unreachable);
			// the policy violation below explains the specific reason.
			fmt.Println("  ✗ CVE check could not run")
		default:
			fmt.Println("  ✓ No critical/high CVEs found")
		}
	}

	if len(result.Failures) > 0 {
		fmt.Printf("\nPolicy violations:\n")
		for _, f := range result.Failures {
			fmt.Printf("  ✗ %s\n", f)
		}
		os.Exit(1)
	}

	fmt.Printf("\n✓ %s verified\n", artifactRef)
	return nil
}

// ── sbom ──────────────────────────────────────────────────────────────────────

func sbomCmd() *cobra.Command {
	var format string
	var attest bool
	var vetDir string

	cmd := &cobra.Command{
		Use:   "sbom <artifact>",
		Short: "Generate and optionally attest an SBOM (requires syft)",
		Long: `Generate a Software Bill of Materials using syft and optionally
attach a signed attestation via cosign.

Requires syft: https://github.com/anchore/syft#installation

Examples:
  vet sbom ghcr.io/org/image:v1.0 --format spdx --attest
  vet sbom ./binary --format cyclonedx`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOM(args[0], vetDir, format, attest)
		},
	}
	cmd.Flags().StringVar(&format, "format", "spdx", "SBOM format: spdx or cyclonedx")
	cmd.Flags().BoolVar(&attest, "attest", false, "attach signed attestation via cosign")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	return cmd
}

func runSBOM(artifactRef, vetDir, format string, attest bool) error {
	s := store.New(vetDir)
	g := sbom.New(s)

	fmt.Printf("Generating %s SBOM for %s...\n", strings.ToUpper(format), artifactRef)
	outPath, err := g.Generate(contextWithTimeout(), artifactRef, format, attest)
	if err != nil {
		return err
	}

	fmt.Printf("✓ SBOM written to %s\n", outPath)
	if attest {
		fmt.Println("✓ SBOM attested via cosign")
	}
	return nil
}

// ── gate ──────────────────────────────────────────────────────────────────────

func gateCmd() *cobra.Command {
	var policyPath string
	var vetDir string
	var tagVetted bool
	var region string

	cmd := &cobra.Command{
		Use:   "gate <artifact>",
		Short: "Evaluate artifact against policy and write Cedar workload attributes",
		Long: `Reads the verification record for an artifact, evaluates it against
.vet/policy.yaml, and writes .vet/gate-result.json with Cedar workload
attributes for attest's Cedar PDP.

attest Cedar policy example:
  permit(principal, action, resource in ResourceGroup::"cui-data")
  when {
    principal.CUITrainingCurrent == true   // from qualify
    && context.workload.SLSALevel >= 2     // from vet
    && context.workload.CVECritical == false
  };

Run 'vet verify' before 'vet gate' to populate the verification record.

For an AWS AMI target (ami-...), --tag-vetted additionally writes the
attest:vetted=true tag to the AMI when the gate passes. That tag is what
ground's AMI-launch-gating SCP requires to permit ec2:RunInstances; a companion
lockdown SCP restricts who may set it, so the principal running this must be the
designated vetter (vet's CI). On a failing gate, no tag is written (fail-closed).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var tagger amitag.Tagger
			if tagVetted {
				if !isAMIRef(args[0]) {
					return fmt.Errorf("--tag-vetted applies only to an AMI target (ami-...), got %q", args[0])
				}
				t, err := amitag.New(cmd.Context(), region)
				if err != nil {
					return err
				}
				tagger = t
			}
			return runGate(cmd.Context(), args[0], vetDir, policyPath, tagger)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", ".vet/policy.yaml", "policy file path")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	cmd.Flags().BoolVar(&tagVetted, "tag-vetted", false, "for an ami-... target: write attest:vetted=true to the AMI when the gate passes")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region for the EC2 tag write (with --tag-vetted)")
	return cmd
}

// isAMIRef reports whether ref is an AWS AMI id (ami-...).
func isAMIRef(ref string) bool {
	return strings.HasPrefix(ref, "ami-")
}

// runGate evaluates the artifact and, when tagger is non-nil and the gate passes
// for an AMI target, writes the attest:vetted tag the launch-gating SCP requires.
func runGate(ctx context.Context, artifactRef, vetDir, policyPath string, tagger amitag.Tagger) error {
	p, err := gate.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	s := store.New(vetDir)
	e := gate.New(s, p)

	result, err := e.Evaluate(ctx, artifactRef)
	if err != nil {
		return err
	}

	if result.MissingRecord {
		fmt.Fprintf(os.Stderr, "warning: no verification record found for %s\n", artifactRef)
		fmt.Fprintf(os.Stderr, "  Run 'vet verify %s' first to populate the record.\n", artifactRef)
		fmt.Fprintf(os.Stderr, "  Proceeding with unverified defaults (fail-closed).\n\n")
	}

	fmt.Printf("Gate evaluation: %s\n\n", artifactRef)
	fmt.Printf("  context.workload.SLSALevel    = %d\n", result.GateResult.SLSALevel)
	fmt.Printf("  context.workload.SBOMPresent  = %v\n", result.GateResult.SBOMPresent)
	fmt.Printf("  context.workload.CVECritical  = %v\n", result.GateResult.CVECritical)
	fmt.Printf("  context.workload.CVEHigh      = %v\n", result.GateResult.CVEHigh)
	fmt.Printf("  context.workload.Signed       = %v\n", result.GateResult.Signed)
	fmt.Println()

	if result.PolicyMet {
		fmt.Printf("✓ Policy met — Cedar attributes written to %s/gate-result.json\n", vetDir)
		tagged, err := tagIfVetted(ctx, tagger, artifactRef, true)
		if err != nil {
			return err
		}
		if tagged {
			fmt.Printf("✓ Tagged AMI %s: %s=true\n", artifactRef, amitag.TagVetted)
		}
		return nil
	}

	fmt.Println("✗ Policy violations:")
	for _, f := range result.Failures {
		fmt.Printf("  • %s\n", f)
	}
	// Fail-closed: no attest:vetted tag is written on a failing gate.
	os.Exit(1)
	return nil
}

// tagIfVetted writes the attest:vetted tag to the AMI only when the gate passed
// and a tagger is configured — the fail-closed marking step ground's launch-gating
// SCP keys on. It is a small pure-ish seam so the pass/fail decision is unit-tested
// without driving the os.Exit path in runGate. Returns whether a tag was written.
func tagIfVetted(ctx context.Context, tagger amitag.Tagger, amiID string, policyMet bool) (bool, error) {
	if tagger == nil || !policyMet {
		return false, nil
	}
	if err := tagger.TagImage(ctx, amiID, map[string]string{amitag.TagVetted: "true"}); err != nil {
		return false, fmt.Errorf("write %s tag to %s: %w", amitag.TagVetted, amiID, err)
	}
	return true, nil
}

// ── ami-reference ───────────────────────────────────────────────────────────────

func amiReferenceCmd() *cobra.Command {
	var pcrs []string
	var region string

	cmd := &cobra.Command{
		Use:   "ami-reference <ami-id>",
		Short: "Record golden boot-measurement (PCR) tags on a vetted AMI",
		Long: `Record a vetted AMI's known-good boot measurements as attest:pcr<N> tags, so a
running instance can later be bound to the vetted image (provabl#13). NitroTPM /
enclave PCRs cannot be computed offline from an AMI — capture them from a trusted
REFERENCE BOOT:

  1. launch the vetted AMI on a trusted instance
  2. nitro attest --device   (or tpm attest --device)
  3. read the measured PCRs from .nitro/attestation.json / .tpm/attestation.json
  4. vet ami-reference ami-… --pcr 0=<hex> --pcr 7=<hex>

These tags are locked to the vetter principal by ground's lockdown SCP (a forgeable
golden PCR would defeat the binding). At launch, pass the tag value to
'nitro/tpm attest --expected-pcr<N>' to enforce the match.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			amiID := args[0]
			if !strings.HasPrefix(amiID, "ami-") {
				return fmt.Errorf("expected an AMI id (ami-...), got %q", amiID)
			}
			if len(pcrs) == 0 {
				return fmt.Errorf("at least one --pcr <index>=<hex> is required")
			}
			tags, err := pcrTagsFromFlags(pcrs)
			if err != nil {
				return err
			}
			tagger, err := amitag.New(cmd.Context(), region)
			if err != nil {
				return err
			}
			if err := tagger.TagImage(cmd.Context(), amiID, tags); err != nil {
				return fmt.Errorf("write golden-PCR tags to %s: %w", amiID, err)
			}
			fmt.Printf("✓ Recorded golden PCR(s) on %s:\n", amiID)
			for k, v := range tags {
				fmt.Printf("  %s = %s\n", k, v)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&pcrs, "pcr", nil, "golden PCR as <index>=<hex> (repeatable), e.g. --pcr 0=ab12…")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region for the EC2 tag write")
	return cmd
}

// pcrTagsFromFlags parses repeated --pcr <index>=<hex> values into attest:pcr<N>
// tag pairs, validating the index (0–23) and that the value is hex.
func pcrTagsFromFlags(pcrs []string) (map[string]string, error) {
	tags := make(map[string]string, len(pcrs))
	for _, p := range pcrs {
		idxStr, val, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("--pcr %q must be <index>=<hex>", p)
		}
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 0 || idx > 23 {
			return nil, fmt.Errorf("--pcr index %q must be 0–23", idxStr)
		}
		if val == "" {
			return nil, fmt.Errorf("--pcr %d has an empty value", idx)
		}
		if _, err := hex.DecodeString(val); err != nil {
			return nil, fmt.Errorf("--pcr %d value must be hex: %w", idx, err)
		}
		tags[fmt.Sprintf("%s%d", amitag.TagPCRPrefix, idx)] = val
	}
	return tags, nil
}

// contextWithTimeout returns a background context.
// Full implementation would use signal.NotifyContext for graceful cancellation.
func contextWithTimeout() context.Context {
	return context.Background()
}
