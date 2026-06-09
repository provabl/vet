// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"testing"
	"time"

	"github.com/provabl/vet/internal/gate"
	"github.com/provabl/vet/internal/store"
)

func seedRecord(t *testing.T, s *store.Store, r *store.VerificationRecord) {
	t.Helper()
	r.VerifiedAt = time.Now()
	if err := s.SaveRecord(r); err != nil {
		t.Fatalf("seed record: %v", err)
	}
}

func TestGateWritesCedarAttributes(t *testing.T) {
	s := store.New(t.TempDir())
	seedRecord(t, s, &store.VerificationRecord{
		ArtifactRef:  "ghcr.io/test/app:v1.0",
		ArtifactHash: "sha256:abc123",
		Signed:       true,
		SLSALevel:    2,
		SBOMPresent:  true,
		CVECritical:  false,
		CVEHigh:      false,
	})

	e := gate.New(s, gate.DefaultPolicy())
	result, err := e.Evaluate(context.Background(), "ghcr.io/test/app:v1.0")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if !result.PolicyMet {
		t.Errorf("policy should be met, failures: %v", result.Failures)
	}
	if result.GateResult.SLSALevel != 2 {
		t.Errorf("SLSALevel = %d, want 2", result.GateResult.SLSALevel)
	}
	if result.GateResult.CVECritical {
		t.Error("CVECritical should be false")
	}
}

func TestGatePolicyViolationMinSLSA(t *testing.T) {
	s := store.New(t.TempDir())
	seedRecord(t, s, &store.VerificationRecord{
		ArtifactRef: "image:v1",
		Signed:      true,
		SLSALevel:   1, // below minimum
	})

	p := &gate.Policy{MinSLSALevel: 2}
	e := gate.New(s, p)
	result, err := e.Evaluate(context.Background(), "image:v1")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.PolicyMet {
		t.Error("policy should NOT be met when SLSA level below minimum")
	}
	if len(result.Failures) == 0 {
		t.Error("expected at least one failure message")
	}
}

func TestGateNoRecordWritesFailClosedResult(t *testing.T) {
	s := store.New(t.TempDir())
	e := gate.New(s, gate.DefaultPolicy())
	result, err := e.Evaluate(context.Background(), "no-record:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.MissingRecord {
		t.Error("expected MissingRecord=true when no record exists")
	}
	if result.PolicyMet {
		t.Error("expected PolicyMet=false (fail-closed) when no record exists")
	}
	if result.GateResult == nil {
		t.Error("expected gate result to be written even when no verification record exists")
	}
	if result.GateResult.Signed || result.GateResult.SLSALevel != 0 {
		t.Error("expected all workload attributes to be false/zero (fail-closed defaults)")
	}
}

func TestGateCVEPolicyViolation(t *testing.T) {
	s := store.New(t.TempDir())
	seedRecord(t, s, &store.VerificationRecord{
		ArtifactRef: "image:v1",
		Signed:      true,
		CVECritical: true,
	})

	p := &gate.Policy{CVEThreshold: "critical"}
	e := gate.New(s, p)
	result, err := e.Evaluate(context.Background(), "image:v1")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.PolicyMet {
		t.Error("policy should NOT be met when critical CVEs found")
	}
}

// A high (but not critical) CVE must fail under the "high" threshold and pass
// under "critical" — the threshold semantics now enforced by the evidence
// appraiser, exercised end-to-end through gate.Evaluate.
func TestGateHighThresholdViaKernel(t *testing.T) {
	s := store.New(t.TempDir())
	seedRecord(t, s, &store.VerificationRecord{
		ArtifactRef: "image:v1",
		Signed:      true,
		CVEHigh:     true,
		CVECritical: false,
	})

	high := gate.New(s, &gate.Policy{CVEThreshold: "high"})
	rHigh, err := high.Evaluate(context.Background(), "image:v1")
	if err != nil {
		t.Fatalf("Evaluate (high): %v", err)
	}
	if rHigh.PolicyMet {
		t.Error("policy should NOT be met: high CVE under high threshold")
	}

	crit := gate.New(s, &gate.Policy{CVEThreshold: "critical"})
	rCrit, err := crit.Evaluate(context.Background(), "image:v1")
	if err != nil {
		t.Fatalf("Evaluate (critical): %v", err)
	}
	if !rCrit.PolicyMet {
		t.Errorf("policy should be met: high CVE under critical threshold, failures: %v", rCrit.Failures)
	}
}
