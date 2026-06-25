// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes external commands (mockable in tests). Mirrors the seam in
// internal/sbom and internal/verify so grype can be driven by a fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type defaultRunner struct{}

func (defaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 — controlled inputs
	return cmd.CombinedOutput()
}

// GrypeSource scans an SBOM document with grype (anchore/grype). Unlike the OSV
// source, grype is **distro-advisory aware**: it consumes the full SBOM document
// (which carries the OS/distro metadata) and matches Amazon Linux / RHEL / Debian
// packages against their distro security feeds (e.g. Amazon ALAS) — not just the
// upstream-kernel-scoped OSV "Linux" ecosystem. This is the source that fixes the
// false-clean gap a naive OSV scan has on a distro AMI (provabl/vet#32).
//
// It requires Target.SBOMPath (the document on disk); Target.Packages is ignored,
// because the lossy package list drops exactly the distro metadata grype needs.
type GrypeSource struct {
	runner Runner
}

// NewGrypeSource returns a GrypeSource using the real command runner.
func NewGrypeSource() *GrypeSource { return &GrypeSource{runner: defaultRunner{}} }

// NewGrypeSourceWithRunner returns a GrypeSource with a custom runner (tests).
func NewGrypeSourceWithRunner(r Runner) *GrypeSource { return &GrypeSource{runner: r} }

// Name identifies the source.
func (*GrypeSource) Name() string { return "grype" }

// Scan runs grype over the target's SBOM document and returns the critical/high
// verdict. Fail-closed: a missing SBOM path, an absent grype binary, a non-zero
// grype exit, or unparseable output all return an error (the gate then denies)
// rather than a falsely-clean verdict.
func (s *GrypeSource) Scan(ctx context.Context, target Target) (Verdict, error) {
	if target.SBOMPath == "" {
		return Verdict{}, fmt.Errorf("grype source requires an SBOM document path (none provided)")
	}
	if err := requireGrype(ctx, s.runner); err != nil {
		return Verdict{}, err
	}
	// grype reads the SBOM document so the distro metadata drives ALAS-aware
	// matching. `sbom:<path>` is grype's explicit SBOM-input scheme.
	out, err := s.runner.Run(ctx, "grype", "sbom:"+target.SBOMPath, "-o", "json")
	if err != nil {
		return Verdict{}, fmt.Errorf("grype: %w\nOutput: %s", err, sanitize(string(out)))
	}
	return parseGrype(out)
}

// requireGrype reports a clear error when the grype binary is not invokable, so a
// requested distro scan that cannot run fails closed rather than silently.
func requireGrype(ctx context.Context, r Runner) error {
	if _, err := r.Run(ctx, "grype", "version"); err != nil {
		return fmt.Errorf("grype not found — install from https://github.com/anchore/grype#installation")
	}
	return nil
}

// grypeReport is the subset of grype's JSON output we read: each match carries a
// vulnerability with a severity string ("Critical", "High", "Medium", …).
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

// parseGrype turns grype's JSON into a Verdict. Scanned counts the matches
// examined (grype reports one match per vulnerable package/vuln pair).
func parseGrype(out []byte) (Verdict, error) {
	var r grypeReport
	if err := json.Unmarshal(out, &r); err != nil {
		return Verdict{}, fmt.Errorf("parse grype output: %w", err)
	}
	v := Verdict{Scanned: len(r.Matches)}
	for _, m := range r.Matches {
		switch strings.ToUpper(m.Vulnerability.Severity) {
		case "CRITICAL":
			v.Critical = true
		case "HIGH":
			v.High = true
		}
	}
	return v, nil
}

// sanitize strips control characters from tool output before it goes into an
// error message.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
