// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/provabl/vet/internal/sbom"
)

// stubTransport returns a canned OSV response (or status) per request.
type stubTransport struct {
	respFor func(body string) (status int, json string)
	calls   int
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls++
	b, _ := io.ReadAll(req.Body)
	status, body := s.respFor(string(b))
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func osvSourceWith(tr *stubTransport) *OSVSource {
	return NewOSVSource(&http.Client{Transport: tr})
}

// scanPkgs scans a package list as a Target (OSV uses Target.Packages).
func scanPkgs(s *OSVSource, pkgs ...sbom.Package) (Verdict, error) {
	return s.Scan(context.Background(), Target{Packages: pkgs})
}

const (
	osvCritical = `{"vulns":[{"id":"GHSA-x","database_specific":{"severity":"CRITICAL"}}]}`
	osvHigh     = `{"vulns":[{"id":"GHSA-y","database_specific":{"severity":"HIGH"}}]}`
	osvClean    = `{}`
)

func TestOSV_Name(t *testing.T) {
	if NewOSVSource(nil).Name() != "osv" {
		t.Error("Name() should be osv")
	}
}

func TestOSV_CriticalFlagged(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 200, osvCritical }}
	v, err := scanPkgs(osvSourceWith(tr), sbom.Package{PURL: "pkg:npm/left-pad@1.0.0"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !v.Critical {
		t.Error("expected Critical")
	}
	if v.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", v.Scanned)
	}
}

func TestOSV_HighFlagged(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 200, osvHigh }}
	v, _ := scanPkgs(osvSourceWith(tr), sbom.Package{PURL: "pkg:npm/x@1.0.0"})
	if v.Critical || !v.High {
		t.Errorf("expected High only, got %+v", v)
	}
}

func TestOSV_CleanPasses(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 200, osvClean }}
	v, err := scanPkgs(osvSourceWith(tr), sbom.Package{PURL: "pkg:npm/safe@1.0.0"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Critical || v.High {
		t.Error("clean package should not flag")
	}
	if v.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", v.Scanned)
	}
}

// A transport error mid-scan must fail closed (error, not a clean verdict).
func TestOSV_TransportErrorFailsClosed(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 503, "" }}
	_, err := scanPkgs(osvSourceWith(tr), sbom.Package{PURL: "pkg:npm/x@1.0.0"})
	if err == nil {
		t.Fatal("expected fail-closed error on OSV 503")
	}
}

// A package with neither PURL nor ecosystem is unresolvable: skipped, not scanned,
// and not an error. This is exactly the AMI/distro gap (a bare rpm name) — the
// OSV source honestly reports it scanned nothing rather than falsely passing it.
func TestOSV_UnresolvablePackageSkipped(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 200, osvClean }}
	v, err := scanPkgs(osvSourceWith(tr), sbom.Package{Name: "bash", Version: "5.2.15"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.Scanned != 0 {
		t.Errorf("Scanned = %d, want 0 (bare name is unresolvable in OSV)", v.Scanned)
	}
	if tr.calls != 0 {
		t.Errorf("expected no OSV calls for an unresolvable package, got %d", tr.calls)
	}
}

func TestOSV_ByEcosystem(t *testing.T) {
	tr := &stubTransport{respFor: func(string) (int, string) { return 200, osvCritical }}
	v, _ := scanPkgs(osvSourceWith(tr), sbom.Package{Name: "django", Version: "3.0", Ecosystem: "PyPI"})
	if !v.Critical || v.Scanned != 1 {
		t.Errorf("ecosystem-keyed package should scan + flag, got %+v", v)
	}
}

func TestOSV_AggregatesAcrossPackages(t *testing.T) {
	// First package clean, second critical → aggregate Critical, Scanned 2.
	tr := &stubTransport{respFor: func(body string) (int, string) {
		if strings.Contains(body, "bad") {
			return 200, osvCritical
		}
		return 200, osvClean
	}}
	v, err := scanPkgs(osvSourceWith(tr),
		sbom.Package{PURL: "pkg:npm/safe@1.0.0"},
		sbom.Package{PURL: "pkg:npm/bad@1.0.0"},
	)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !v.Critical || v.Scanned != 2 {
		t.Errorf("expected Critical with Scanned=2, got %+v", v)
	}
}
