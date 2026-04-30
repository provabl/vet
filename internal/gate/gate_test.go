// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
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
	result, err := e.Evaluate("ghcr.io/test/app:v1.0")
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
	result, err := e.Evaluate("image:v1")
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

func TestGateNoRecordReturnsError(t *testing.T) {
	s := store.New(t.TempDir())
	e := gate.New(s, gate.DefaultPolicy())
	_, err := e.Evaluate("no-record:latest")
	if err == nil {
		t.Error("expected error when no record exists")
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
	result, err := e.Evaluate("image:v1")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.PolicyMet {
		t.Error("policy should NOT be met when critical CVEs found")
	}
}
