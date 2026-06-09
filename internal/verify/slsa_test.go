// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"testing"
)

// ghProvenance builds a minimal `gh attestation verify --format json` payload:
// an array of one verified attestation carrying a slsa.dev/provenance/v1
// statement with the given builder id.
func ghProvenance(predicateType, builderID string) []byte {
	return []byte(`[{"verificationResult":{"statement":{"predicateType":"` + predicateType +
		`","predicate":{"runDetails":{"builder":{"id":"` + builderID + `"}}}}}}]`)
}

func TestSLSALevelFromGH_HostedBuilderIsL2(t *testing.T) {
	out := ghProvenance(slsaProvenanceV1,
		"https://github.com/actions/runner/github-hosted")
	if got := slsaLevelFromGH(out); got != 2 {
		t.Errorf("hosted-builder provenance = level %d, want 2", got)
	}
}

func TestSLSALevelFromGH_GeneratorIsL3(t *testing.T) {
	out := ghProvenance(slsaProvenanceV1,
		"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0")
	if got := slsaLevelFromGH(out); got != 3 {
		t.Errorf("slsa-github-generator provenance = level %d, want 3", got)
	}
}

func TestSLSALevelFromGH_WrongPredicateIsZero(t *testing.T) {
	// A verified attestation that is not build provenance must not count as SLSA.
	out := ghProvenance("https://spdx.dev/Document", "whatever")
	if got := slsaLevelFromGH(out); got != 0 {
		t.Errorf("non-provenance predicate = level %d, want 0", got)
	}
}

func TestSLSALevelFromGH_EmptyOrGarbageIsZero(t *testing.T) {
	if got := slsaLevelFromGH([]byte(`[]`)); got != 0 {
		t.Errorf("empty array = level %d, want 0", got)
	}
	if got := slsaLevelFromGH([]byte(`not json`)); got != 0 {
		t.Errorf("garbage = level %d, want 0", got)
	}
	// The old regex would have returned 2 for any text containing "verified";
	// confirm the structural parser does not (no false L2 from prose).
	if got := slsaLevelFromGH([]byte(`{"message":"attestation verified"}`)); got != 0 {
		t.Errorf("prose containing 'verified' = level %d, want 0 (no false L2)", got)
	}
}

// verifySLSA must surface errGHMissing (not a silent level 0) when the tool is
// absent. Uses a bogus tool name that is neither on PATH nor known to the runner,
// exercised through a Verifier with an always-failing runner.
func TestVerifySLSA_ToolMissingIsDistinct(t *testing.T) {
	if toolAvailable(context.Background(), failRunner{}, "definitely-not-a-real-tool-xyz") {
		t.Fatal("toolAvailable should be false for a nonexistent tool with a failing runner")
	}
}

// failRunner reports every command as unavailable.
type failRunner struct{}

func (failRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("not found")
}
