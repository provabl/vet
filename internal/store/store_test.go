// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"testing"
	"time"

	"github.com/provabl/vet/internal/store"
)

func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	rec := &store.VerificationRecord{
		ArtifactRef:  "ghcr.io/test/image:v1.0",
		ArtifactHash: "sha256:abc123",
		Signed:       true,
		SLSALevel:    2,
		SBOMPresent:  true,
		CVECritical:  false,
		VerifiedAt:   time.Now().Truncate(time.Second),
	}

	if err := s.SaveRecord(rec); err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}

	got, err := s.LoadRecord(rec.ArtifactRef)
	if err != nil {
		t.Fatalf("LoadRecord: %v", err)
	}
	if got == nil {
		t.Fatal("LoadRecord returned nil — record not found")
	}
	if got.SLSALevel != 2 {
		t.Errorf("SLSALevel = %d, want 2", got.SLSALevel)
	}
	if !got.Signed {
		t.Error("Signed should be true")
	}
}

func TestLoadRecordNotFound(t *testing.T) {
	s := store.New(t.TempDir())
	rec, err := s.LoadRecord("nonexistent:artifact")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Error("expected nil record for unknown artifact")
	}
}

func TestGateResultRoundtrip(t *testing.T) {
	s := store.New(t.TempDir())
	g := &store.GateResult{
		Artifact:    "image:tag",
		SLSALevel:   2,
		SBOMPresent: true,
		CVECritical: false,
		Signed:      true,
		PolicyMet:   true,
		EvaluatedAt: time.Now().Truncate(time.Second),
	}
	if err := s.SaveGateResult(g); err != nil {
		t.Fatalf("SaveGateResult: %v", err)
	}
}
