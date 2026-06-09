// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/provabl/vet/internal/gate"
	"github.com/provabl/vet/internal/sbom"
	"github.com/provabl/vet/internal/sign"
	"github.com/provabl/vet/internal/store"
	"github.com/provabl/vet/internal/verify"
)

var version = "0.1.1"

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
	cmd.AddCommand(signCmd(), verifyCmd(), sbomCmd(), gateCmd())
	return cmd
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

	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify SLSA provenance and CVE status of an artifact",
		Long: `Verify a container image or binary against configured policy.
Checks: cosign signature, SLSA provenance (via gh CLI), CVE status (via OSV API).

Exit codes: 0 = verified, 1 = policy violation, 2 = error

Examples:
  vet verify ghcr.io/org/image:v1.0 --source github.com/org/repo --min-slsa-level 2
  vet verify ghcr.io/org/image:v1.0 --check-cves critical
  vet verify ./binary --source github.com/org/repo`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0], vetDir, verify.Options{
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
	return cmd
}

func runVerify(artifactRef, vetDir string, opts verify.Options) error {
	s := store.New(vetDir)
	v := verify.New(s)

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
		if result.SLSALevel > 0 {
			fmt.Printf("  ✓ SLSA Level %d provenance verified\n", result.SLSALevel)
		} else {
			fmt.Println("  ✗ SLSA provenance not found or unverified")
		}
	}

	if opts.CheckCVEs != "" {
		if !result.CVECritical && !result.CVEHigh {
			fmt.Println("  ✓ No critical/high CVEs found")
		} else {
			if result.CVECritical {
				fmt.Println("  ✗ Critical CVEs found")
			}
			if result.CVEHigh {
				fmt.Println("  ✗ High CVEs found")
			}
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

Run 'vet verify' before 'vet gate' to populate the verification record.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGate(cmd.Context(), args[0], vetDir, policyPath)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", ".vet/policy.yaml", "policy file path")
	cmd.Flags().StringVar(&vetDir, "vet-dir", ".vet", ".vet directory path")
	return cmd
}

func runGate(ctx context.Context, artifactRef, vetDir, policyPath string) error {
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
		return nil
	}

	fmt.Println("✗ Policy violations:")
	for _, f := range result.Failures {
		fmt.Printf("  • %s\n", f)
	}
	os.Exit(1)
	return nil
}

// contextWithTimeout returns a background context.
// Full implementation would use signal.NotifyContext for graceful cancellation.
func contextWithTimeout() context.Context {
	return context.Background()
}
