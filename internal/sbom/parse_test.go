// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/provabl/vet/internal/sbom"
)

func TestLoad_SPDX(t *testing.T) {
	pkgs, err := sbom.Load("testdata/sample.spdx.json")
	if err != nil {
		t.Fatalf("Load SPDX: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	// PURL preferred + ecosystem derived.
	got := byName(pkgs)
	if p := got["github.com/foo/bar"]; p.PURL != "pkg:golang/github.com/foo/bar@v1.2.3" || p.Ecosystem != "Go" || p.Version != "v1.2.3" {
		t.Errorf("go package wrong: %+v", p)
	}
	if p := got["left-pad"]; p.Ecosystem != "npm" {
		t.Errorf("npm package ecosystem = %q, want npm", p.Ecosystem)
	}
}

func TestLoad_CycloneDX(t *testing.T) {
	pkgs, err := sbom.Load("testdata/sample.cyclonedx.json")
	if err != nil {
		t.Fatalf("Load CycloneDX: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	got := byName(pkgs)
	if p := got["requests"]; p.Ecosystem != "PyPI" || p.PURL != "pkg:pypi/requests@2.20.0" {
		t.Errorf("pypi package wrong: %+v", p)
	}
}

func TestLoad_AbsentIsErrNoSBOM(t *testing.T) {
	_, err := sbom.Load(filepath.Join(t.TempDir(), "nope.spdx.json"))
	if !errors.Is(err, sbom.ErrNoSBOM) {
		t.Errorf("expected ErrNoSBOM, got %v", err)
	}
}

func TestLoad_MalformedErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.spdx.json")
	// Has the SPDX sniff marker but is invalid JSON.
	if err := os.WriteFile(p, []byte(`{"spdxVersion":"SPDX-2.3" "packages"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sbom.Load(p); err == nil {
		t.Error("expected parse error for malformed SPDX")
	}
}

func TestParse_UnknownFormat(t *testing.T) {
	if _, err := sbom.Parse([]byte(`{"hello":"world"}`), "x.json"); err == nil {
		t.Error("expected error for unrecognized SBOM format")
	}
}

func TestParse_EmptyPackages(t *testing.T) {
	_, err := sbom.Parse([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`), "empty.json")
	if !errors.Is(err, sbom.ErrEmptySBOM) {
		t.Errorf("expected ErrEmptySBOM, got %v", err)
	}
}

func byName(pkgs []sbom.Package) map[string]sbom.Package {
	m := make(map[string]sbom.Package, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}
