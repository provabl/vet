// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package sbom generates and attests Software Bills of Materials using syft
// for generation and cosign for attestation.
package sbom

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/provabl/vet/internal/store"
)

// Runner executes external commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type defaultRunner struct{}

func (r *defaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 — controlled inputs
	return cmd.CombinedOutput()
}

// Generator produces and attests SBOMs.
type Generator struct {
	runner Runner
	store  *store.Store
}

// New creates a Generator.
func New(s *store.Store) *Generator {
	return &Generator{runner: &defaultRunner{}, store: s}
}

// NewWithRunner creates a Generator with a custom runner (for testing).
func NewWithRunner(r Runner, s *store.Store) *Generator {
	return &Generator{runner: r, store: s}
}

// Generate creates an SBOM for the given artifact and optionally attests it.
// format: "spdx" or "cyclonedx"
func (g *Generator) Generate(ctx context.Context, artifactRef, format string, attest bool) (string, error) {
	if err := requireSyft(ctx, g.runner); err != nil {
		return "", err
	}

	outPath := g.store.SBOMPath(artifactRef, format)

	// Map format name to syft output spec.
	syftFormat := "spdx-json"
	if strings.Contains(format, "cyclonedx") {
		syftFormat = "cyclonedx-json"
	}

	out, err := g.runner.Run(ctx, "syft", artifactRef, "-o", syftFormat, "--file", outPath)
	if err != nil {
		return "", fmt.Errorf("syft: %w\nOutput: %s", err, sanitize(string(out)))
	}

	// Attest if requested (container images only).
	if attest && looksLikeImage(artifactRef) {
		predicateType := "spdxjson"
		if strings.Contains(format, "cyclonedx") {
			predicateType = "cyclonedxjson"
		}
		attestOut, attestErr := g.runner.Run(ctx, "cosign", "attest",
			"--yes",
			"--predicate", outPath,
			"--type", predicateType,
			artifactRef)
		if attestErr != nil {
			return outPath, fmt.Errorf("cosign attest: %w\nOutput: %s", attestErr, sanitize(string(attestOut)))
		}
	}

	return outPath, nil
}

func requireSyft(ctx context.Context, r Runner) error {
	if _, err := r.Run(ctx, "syft", "version"); err != nil {
		return fmt.Errorf("syft not found — install from https://github.com/anchore/syft#installation")
	}
	return nil
}

func looksLikeImage(ref string) bool {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "/") {
		return false
	}
	return strings.Contains(ref, ":") || strings.Contains(ref, "@")
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
