// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package vetasp_test

import (
	"context"
	"sort"
	"testing"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/term"

	vetasp "github.com/provabl/vet/internal/evidence"
	"github.com/provabl/vet/internal/store"
)

// stubSource returns a fixed record (or nil for the missing-record case) for any
// target, so the provider tests run with no store and no filesystem.
type stubSource struct{ rec *store.VerificationRecord }

func (s stubSource) Fetch(context.Context, term.Target) (*store.VerificationRecord, error) {
	return s.rec, nil
}

// appraise builds the CVM, runs the canonical term, and appraises — the same
// path gate.Evaluate drives. Returns the appraised verdict.
func appraise(t *testing.T, rec *store.VerificationRecord, params term.Params) asp.Verdict {
	t.Helper()
	reg := asp.NewRegistry()
	if err := reg.Register(vetasp.Provider(stubSource{rec: rec})); err != nil {
		t.Fatalf("register: %v", err)
	}
	am, err := vetasp.NewEphemeralAM()
	if err != nil {
		t.Fatalf("am: %v", err)
	}
	c := cvm.New(reg, am, am, nil)
	protocol := term.Seq(
		term.Nonce(),
		term.Seq(term.Meas(term.Self, vetasp.ID, vetasp.Target("ghcr.io/test/app:v1.0"), params), term.Sig()),
	)
	bundle, ch, err := c.Run(context.Background(), protocol)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	v, err := c.Appraise(context.Background(), bundle, ch)
	if err != nil {
		t.Fatalf("appraise: %v", err)
	}
	return v
}

func signedRecord() *store.VerificationRecord {
	return &store.VerificationRecord{
		ArtifactRef:  "ghcr.io/test/app:v1.0",
		ArtifactHash: "sha256:abc123",
		Signed:       true,
		SLSALevel:    2,
		SBOMPresent:  true,
	}
}

func TestProvider_PassEmitsFullClaimSet(t *testing.T) {
	v := appraise(t, signedRecord(), term.Params{"min_slsa_level": "2", "cve_threshold": "critical"})
	if !v.Pass {
		t.Fatalf("expected pass, reason: %s", v.Reason)
	}

	attrs := lower.ToAttributes(v)
	// Golden: the exact Cedar workload key set the contract requires.
	want := map[string]string{
		"workload.SLSALevel":    "long",
		"workload.SBOMPresent":  "bool",
		"workload.CVECritical":  "bool",
		"workload.CVEHigh":      "bool",
		"workload.Signed":       "bool",
		"workload.ArtifactHash": "string",
		"attested":              "bool", // synthesized by lower.ToAttributes
	}
	for k, typ := range want {
		a, ok := attrs[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if a.Type != typ {
			t.Errorf("attr %q type = %q, want %q", k, a.Type, typ)
		}
	}
	// No stray workload keys beyond the contract (catches accidental additions).
	var got []string
	for k := range attrs {
		got = append(got, k)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Errorf("attribute set = %v (%d), want %d keys", got, len(got), len(want))
	}
	if attrs["workload.SLSALevel"].Value != "2" {
		t.Errorf("SLSALevel = %q, want 2", attrs["workload.SLSALevel"].Value)
	}
	if attrs["attested"].Value != "true" {
		t.Errorf("attested = %q, want true", attrs["attested"].Value)
	}
}

func TestProvider_FailBelowMinSLSA(t *testing.T) {
	rec := signedRecord()
	rec.SLSALevel = 1
	v := appraise(t, rec, term.Params{"min_slsa_level": "2"})
	if v.Pass {
		t.Fatal("expected fail for SLSA 1 < min 2")
	}
}

func TestProvider_FailCritical(t *testing.T) {
	rec := signedRecord()
	rec.CVECritical = true
	v := appraise(t, rec, term.Params{"cve_threshold": "critical"})
	if v.Pass {
		t.Fatal("expected fail for critical CVE under critical threshold")
	}
}

// The "high" threshold semantics the kernel reference provider lacks: a record
// with a HIGH (but not critical) CVE must FAIL under cve_threshold=high, and
// PASS under cve_threshold=critical. Proves high != critical.
func TestProvider_HighThresholdDistinctFromCritical(t *testing.T) {
	rec := signedRecord()
	rec.CVEHigh = true
	rec.CVECritical = false

	vHigh := appraise(t, rec, term.Params{"cve_threshold": "high"})
	if vHigh.Pass {
		t.Error("expected FAIL: high CVE under high threshold")
	}

	vCrit := appraise(t, rec, term.Params{"cve_threshold": "critical"})
	if !vCrit.Pass {
		t.Errorf("expected PASS: high CVE under critical threshold, reason: %s", vCrit.Reason)
	}
}

// Freshness: a bundle appraised against a DIFFERENT challenge than the one issued
// must fail at the spine before any workload claim is trusted.
func TestProvider_FreshnessNonceMismatch(t *testing.T) {
	reg := asp.NewRegistry()
	if err := reg.Register(vetasp.Provider(stubSource{rec: signedRecord()})); err != nil {
		t.Fatal(err)
	}
	am, err := vetasp.NewEphemeralAM()
	if err != nil {
		t.Fatal(err)
	}
	c := cvm.New(reg, am, am, nil)
	protocol := term.Seq(
		term.Nonce(),
		term.Seq(term.Meas(term.Self, vetasp.ID, vetasp.Target("x"), term.Params{}), term.Sig()),
	)
	bundle, _, err := c.Run(context.Background(), protocol)
	if err != nil {
		t.Fatal(err)
	}
	// Appraise with a fresh, unrelated challenge — the issued nonce is discarded.
	stale := cvm.Challenge{Nonce: []byte("a-different-32-byte-challenge....")}
	v, err := c.Appraise(context.Background(), bundle, stale)
	if err != nil {
		t.Fatal(err)
	}
	if v.Pass {
		t.Fatal("expected freshness failure on nonce mismatch")
	}
}

// Missing record: the measurer reports CollectFailed; appraisal fails and emits
// no workload.* claims, only the kernel's vet.collected=false marker.
func TestProvider_MissingRecord(t *testing.T) {
	v := appraise(t, nil, term.Params{})
	if v.Pass {
		t.Fatal("expected fail when no record exists")
	}
	attrs := lower.ToAttributes(v)
	if _, ok := attrs["workload.Signed"]; ok {
		t.Error("expected no workload.* claims on a CollectFailed measurement")
	}
	if attrs["vet.collected"].Value != "false" {
		t.Errorf("expected vet.collected=false, got %q", attrs["vet.collected"].Value)
	}
}
