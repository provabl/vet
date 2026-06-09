// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package sign wraps the cosign CLI for keyless artifact signing.
// All signing operations use Sigstore keyless signing (no private key needed).
// Identity comes from GitHub Actions OIDC or browser-based OIDC for interactive use.
package sign

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/provabl/vet/internal/store"
)

// Runner executes external commands. Interface enables mocking in tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// defaultRunner executes real commands.
type defaultRunner struct{}

func (r *defaultRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 — controlled inputs
	out, err := cmd.CombinedOutput()
	return out, err
}

// Signer signs artifacts using the cosign CLI.
type Signer struct {
	runner  Runner
	store   *store.Store
	yes     bool // skip interactive confirmation (--yes)
}

// New creates a Signer with the given store and options.
func New(s *store.Store, yes bool) *Signer {
	return &Signer{runner: &defaultRunner{}, store: s, yes: yes}
}

// NewWithRunner creates a Signer with a custom runner (for testing).
func NewWithRunner(r Runner, s *store.Store) *Signer {
	return &Signer{runner: r, store: s, yes: true}
}

// SignResult is returned from a successful sign operation.
type SignResult struct {
	ArtifactRef  string
	ArtifactHash string
	RekorLogID   string
	SignerSubject string
}

// Sign signs an artifact using cosign keyless signing.
// For container images, uses `cosign sign`. For blobs, uses `cosign sign-blob`.
// The subject is embedded in the OIDC certificate (GitHub Actions workflow path).
func (s *Signer) Sign(ctx context.Context, artifactRef string) (*SignResult, error) {
	if strings.HasPrefix(artifactRef, "-") {
		return nil, fmt.Errorf("invalid artifact ref %q: cannot start with a flag character (-)", artifactRef)
	}
	if err := requireCosign(ctx, s.runner); err != nil {
		return nil, err
	}

	isImage := looksLikeImage(artifactRef)
	var out []byte
	var runErr error

	if isImage {
		args := []string{"sign"}
		if s.yes {
			args = append(args, "--yes")
		}
		args = append(args, artifactRef)
		out, runErr = s.runner.Run(ctx, "cosign", args...)
	} else {
		// Local file — use sign-blob
		sigFile := artifactRef + ".sig"
		args := []string{"sign-blob"}
		if s.yes {
			args = append(args, "--yes")
		}
		args = append(args, "--output-signature", sigFile, artifactRef)
		out, runErr = s.runner.Run(ctx, "cosign", args...)
	}

	if runErr != nil {
		return nil, fmt.Errorf("cosign sign: %w\nOutput: %s", runErr, sanitize(string(out)))
	}

	result := &SignResult{
		ArtifactRef: artifactRef,
	}
	result.RekorLogID = extractRekorID(string(out))

	// Write record.
	rec := &store.VerificationRecord{
		ArtifactRef: artifactRef,
		Signed:      true,
		RekorLogID:  result.RekorLogID,
		VerifiedAt:  time.Now(),
	}
	if err := s.store.SaveRecord(rec); err != nil {
		// Non-fatal — sign succeeded even if record write fails.
		fmt.Fprintf(os.Stderr, "warning: could not save record: %v\n", err)
	}

	return result, nil
}

// requireCosign checks that cosign is installed and returns a helpful error if not.
func requireCosign(ctx context.Context, r Runner) error {
	if _, err := r.Run(ctx, "cosign", "version"); err != nil {
		return fmt.Errorf("cosign not found — install from https://docs.sigstore.dev/cosign/system_config/installation/")
	}
	return nil
}

// looksLikeImage returns true for container image references (contain : or @).
func looksLikeImage(ref string) bool {
	// Has a registry or tag separator but no path separator (not a local file)
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "/") {
		return false
	}
	return strings.Contains(ref, ":") || strings.Contains(ref, "@")
}

// extractRekorID finds the Rekor transparency log entry ID from cosign output.
var rekorIDRe = regexp.MustCompile(`(?i)rekor\s+log\s+index[:\s]+(\d+)`)

func extractRekorID(output string) string {
	if m := rekorIDRe.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return ""
}

// sanitize strips ANSI escape codes and control chars from external command output
// before printing to terminal (prevents terminal injection).
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitize(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
