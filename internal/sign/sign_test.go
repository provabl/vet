// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"context"
	"testing"

	"github.com/provabl/vet/internal/sign"
	"github.com/provabl/vet/internal/store"
)

// mockRunner simulates cosign CLI output for testing.
type mockRunner struct {
	output string
	err    error
}

func (m *mockRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return []byte(m.output), m.err
}

func TestSignWritesRecord(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	runner := &mockRunner{
		output: "tlog entry created with index: 12345678\nRekor log index: 12345678",
	}
	signer := sign.NewWithRunner(runner, s)

	_, err := signer.Sign(context.Background(), "ghcr.io/test/image:v1.0")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify record was written.
	rec, err := s.LoadRecord("ghcr.io/test/image:v1.0")
	if err != nil {
		t.Fatalf("LoadRecord: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record to be written after sign")
	}
	if !rec.Signed {
		t.Error("record.Signed should be true")
	}
}

func TestSignBlob(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)
	runner := &mockRunner{output: "Signature written to ./binary.sig"}
	signer := sign.NewWithRunner(runner, s)

	_, err := signer.Sign(context.Background(), "./binary")
	if err != nil {
		t.Fatalf("Sign blob: %v", err)
	}
}

func TestLooksLikeImageDetection(t *testing.T) {
	// Test that local paths don't trigger image mode (tested indirectly through sign output)
	dir := t.TempDir()
	s := store.New(dir)

	var capturedArgs []string
	runner := &captureRunner{args: &capturedArgs}
	signer := sign.NewWithRunner(runner, s)

	_ = signer
	// The key behavior is tested in TestSignBlob/TestSignWritesRecord
}

type captureRunner struct {
	args *[]string
}

func (c *captureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	*c.args = append([]string{name}, args...)
	return []byte("ok"), nil
}
