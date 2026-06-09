// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provabl/vet/internal/store"
)

// recordingRunner records each command and returns scripted results. failVersion
// makes `syft version` fail (tool-absent case); otherwise commands succeed.
type recordingRunner struct {
	calls       [][]string
	failVersion bool
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "syft" && len(args) > 0 && args[0] == "version" {
		if r.failVersion {
			return nil, errors.New("not found")
		}
	}
	return []byte("ok"), nil
}

func (r *recordingRunner) ran(tool string) bool {
	for _, c := range r.calls {
		if c[0] == tool && !(len(c) > 1 && c[1] == "version") {
			return true
		}
	}
	return false
}

func TestGenerate_RunsSyft(t *testing.T) {
	r := &recordingRunner{}
	g := NewWithRunner(r, store.New(t.TempDir()))

	path, err := g.Generate(context.Background(), "ghcr.io/org/app:v1", "spdx", false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasSuffix(path, ".spdx.json") {
		t.Errorf("output path = %q, want .spdx.json suffix", path)
	}
	if !r.ran("syft") {
		t.Error("expected syft to be invoked")
	}
	if r.ran("cosign") {
		t.Error("cosign should not run without --attest")
	}
}

func TestGenerate_AttestRunsCosign(t *testing.T) {
	r := &recordingRunner{}
	g := NewWithRunner(r, store.New(t.TempDir()))

	if _, err := g.Generate(context.Background(), "ghcr.io/org/app:v1", "spdx", true); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !r.ran("cosign") {
		t.Error("expected cosign attest to run for an image with --attest")
	}
}

func TestGenerate_NoAttestForLocalFile(t *testing.T) {
	r := &recordingRunner{}
	g := NewWithRunner(r, store.New(t.TempDir()))

	// Local path: attest requested but skipped (cosign attest is image-only).
	if _, err := g.Generate(context.Background(), "./binary", "spdx", true); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r.ran("cosign") {
		t.Error("cosign attest should be skipped for a local-file artifact")
	}
}

func TestGenerate_MissingSyftErrors(t *testing.T) {
	r := &recordingRunner{failVersion: true}
	g := NewWithRunner(r, store.New(t.TempDir()))

	_, err := g.Generate(context.Background(), "ghcr.io/org/app:v1", "spdx", false)
	if err == nil || !strings.Contains(err.Error(), "syft") {
		t.Fatalf("expected a syft-not-found error, got %v", err)
	}
	if r.ran("syft") {
		t.Error("syft generation should not run when the version check fails")
	}
}

func TestGenerate_CycloneDXFormat(t *testing.T) {
	r := &recordingRunner{}
	g := NewWithRunner(r, store.New(t.TempDir()))

	path, err := g.Generate(context.Background(), "ghcr.io/org/app:v1", "cyclonedx", false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasSuffix(path, ".cyclonedx.json") {
		t.Errorf("output path = %q, want .cyclonedx.json suffix", path)
	}
}
