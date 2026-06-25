// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner serves canned output/errors keyed by the first argument, so grype's
// `version` probe and the scan invocation can be answered independently.
type fakeRunner struct {
	versionErr error    // returned for `grype version`
	scanOut    string   // returned for `grype sbom:...`
	scanErr    error    // returned for `grype sbom:...`
	gotArgs    []string // records the scan args for assertions
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "version" {
		return []byte("grype 0.x"), f.versionErr
	}
	f.gotArgs = append([]string{name}, args...)
	return []byte(f.scanOut), f.scanErr
}

const grypeCritical = `{"matches":[{"vulnerability":{"severity":"Critical"}},{"vulnerability":{"severity":"Medium"}}]}`
const grypeHigh = `{"matches":[{"vulnerability":{"severity":"High"}}]}`
const grypeClean = `{"matches":[]}`

func TestGrype_Name(t *testing.T) {
	if NewGrypeSource().Name() != "grype" {
		t.Error("Name() should be grype")
	}
}

func TestGrype_CriticalFlagged(t *testing.T) {
	r := &fakeRunner{scanOut: grypeCritical}
	v, err := NewGrypeSourceWithRunner(r).Scan(context.Background(), Target{SBOMPath: "/tmp/sbom.json"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !v.Critical || v.Scanned != 2 {
		t.Errorf("expected Critical with Scanned=2, got %+v", v)
	}
	// grype must be driven over the SBOM document (so distro metadata is present).
	joined := strings.Join(r.gotArgs, " ")
	if !strings.Contains(joined, "sbom:/tmp/sbom.json") {
		t.Errorf("expected grype to scan the SBOM document, got args: %v", r.gotArgs)
	}
}

func TestGrype_HighFlagged(t *testing.T) {
	v, err := NewGrypeSourceWithRunner(&fakeRunner{scanOut: grypeHigh}).
		Scan(context.Background(), Target{SBOMPath: "/tmp/s.json"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Critical || !v.High {
		t.Errorf("expected High only, got %+v", v)
	}
}

func TestGrype_CleanPasses(t *testing.T) {
	v, err := NewGrypeSourceWithRunner(&fakeRunner{scanOut: grypeClean}).
		Scan(context.Background(), Target{SBOMPath: "/tmp/s.json"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Critical || v.High || v.Scanned != 0 {
		t.Errorf("expected clean empty verdict, got %+v", v)
	}
}

// No SBOM path → fail closed (grype needs the document for distro matching).
func TestGrype_NoSBOMPathFailsClosed(t *testing.T) {
	_, err := NewGrypeSourceWithRunner(&fakeRunner{scanOut: grypeClean}).
		Scan(context.Background(), Target{})
	if err == nil {
		t.Fatal("expected error when no SBOM path is provided")
	}
}

// grype binary absent → fail closed with an install hint.
func TestGrype_MissingBinaryFailsClosed(t *testing.T) {
	r := &fakeRunner{versionErr: errors.New("exec: grype not found")}
	_, err := NewGrypeSourceWithRunner(r).Scan(context.Background(), Target{SBOMPath: "/tmp/s.json"})
	if err == nil || !strings.Contains(err.Error(), "grype not found") {
		t.Fatalf("expected missing-binary fail-closed, got %v", err)
	}
}

// grype exits non-zero → fail closed.
func TestGrype_ScanErrorFailsClosed(t *testing.T) {
	r := &fakeRunner{scanErr: errors.New("exit status 1"), scanOut: "boom"}
	_, err := NewGrypeSourceWithRunner(r).Scan(context.Background(), Target{SBOMPath: "/tmp/s.json"})
	if err == nil {
		t.Fatal("expected fail-closed on grype non-zero exit")
	}
}

// Unparseable grype output → fail closed (never a silent clean pass).
func TestGrype_BadJSONFailsClosed(t *testing.T) {
	r := &fakeRunner{scanOut: "not json"}
	_, err := NewGrypeSourceWithRunner(r).Scan(context.Background(), Target{SBOMPath: "/tmp/s.json"})
	if err == nil {
		t.Fatal("expected fail-closed on unparseable grype output")
	}
}
