// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/provabl/vet/internal/cve"
	"github.com/provabl/vet/internal/store"
)

// stubTransport returns canned OSV responses keyed by whether the request body
// names a package we want to flag. respFor is called per request body.
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

// newTestVerifier builds a Verifier with a temp store, a no-op Runner (so the
// cosign/gh steps don't shell out), and an http.Client backed by the given OSV
// stub transport.
func newTestVerifier(t *testing.T, osv *stubTransport) (*Verifier, *store.Store) {
	t.Helper()
	s := store.New(t.TempDir())
	v := NewWithRunner(stubRunner{}, s)
	client := &http.Client{Transport: osv}
	v.http = client
	// Point the CVE source at the same stub transport so checkCVEs delegates to a
	// fake OSV (the seam keeps the existing OSV behaviour as the default source).
	v.WithCVESource(cve.NewOSVSource(client))
	return v, s
}

type stubRunner struct{}

// Run errors so verifySig/verifySLSA treat the artifact as unsigned / no
// provenance — fine, these tests are about the CVE gate.
func (stubRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, os.ErrNotExist
}

// seedSPDX writes an SPDX SBOM with one package (purl) into the store for ref.
func seedSPDX(t *testing.T, s *store.Store, ref, purl string) {
	t.Helper()
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	doc := `{"spdxVersion":"SPDX-2.3","packages":[{"name":"p","versionInfo":"1.0",` +
		`"externalRefs":[{"referenceType":"purl","referenceLocator":"` + purl + `"}]}]}`
	if err := os.WriteFile(s.SBOMPath(ref, "spdx"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

const osvCritical = `{"vulns":[{"id":"GHSA-x","database_specific":{"severity":"CRITICAL"}}]}`
const osvClean = `{}`

func TestCheckCVEs_CriticalFlagged(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 200, osvCritical }}
	v, s := newTestVerifier(t, osv)
	seedSPDX(t, s, "img:v1", "pkg:npm/left-pad@1.0.0")

	crit, _, ran, err := v.checkCVEs(context.Background(), "img:v1")
	if err != nil || !ran {
		t.Fatalf("expected check to run cleanly, ran=%v err=%v", ran, err)
	}
	if !crit {
		t.Error("expected CVECritical=true")
	}
	if osv.calls != 1 {
		t.Errorf("expected 1 OSV call, got %d", osv.calls)
	}
}

func TestCheckCVEs_CleanPasses(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 200, osvClean }}
	v, s := newTestVerifier(t, osv)
	seedSPDX(t, s, "img:v1", "pkg:npm/safe@1.0.0")

	crit, high, ran, err := v.checkCVEs(context.Background(), "img:v1")
	if err != nil || !ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	if crit || high {
		t.Error("expected no critical/high for a clean package")
	}
}

func TestCheckCVEs_NoSBOMDoesNotRun(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 200, osvClean }}
	v, _ := newTestVerifier(t, osv) // no SBOM seeded
	_, _, ran, err := v.checkCVEs(context.Background(), "img:v1")
	if ran {
		t.Fatal("expected ran=false when no SBOM present")
	}
	if err == nil {
		t.Fatal("expected an error explaining the missing SBOM")
	}
}

func TestCheckCVEs_OSVErrorDoesNotRun(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 503, "" }}
	v, s := newTestVerifier(t, osv)
	seedSPDX(t, s, "img:v1", "pkg:npm/x@1.0.0")
	_, _, ran, err := v.checkCVEs(context.Background(), "img:v1")
	if ran || err == nil {
		t.Fatalf("expected fail-closed on OSV error: ran=%v err=%v", ran, err)
	}
}

// The security regression: --check-cves with no SBOM must DENY, not silently pass.
func TestVerify_CheckCVEsNoSBOMFailsClosed(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 200, osvClean }}
	v, _ := newTestVerifier(t, osv)

	res, err := v.Verify(context.Background(), "img:v1", Options{CheckCVEs: "critical"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.PolicyMet {
		t.Fatal("SECURITY: --check-cves with no SBOM passed — must fail closed")
	}
	var found bool
	for _, f := range res.Failures {
		if strings.Contains(f, "CVE check requested but could not run") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a fail-closed CVE reason, got: %v", res.Failures)
	}
}

// With a critical CVE in the SBOM, --check-cves critical must DENY.
func TestVerify_CheckCVEsCriticalDenies(t *testing.T) {
	osv := &stubTransport{respFor: func(string) (int, string) { return 200, osvCritical }}
	v, s := newTestVerifier(t, osv)
	seedSPDX(t, s, "img:v1", "pkg:npm/bad@1.0.0")

	res, err := v.Verify(context.Background(), "img:v1", Options{CheckCVEs: "critical"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.PolicyMet {
		t.Fatal("expected DENY for an artifact with a critical CVE")
	}
	if !res.CVECritical {
		t.Error("expected CVECritical=true")
	}
}
