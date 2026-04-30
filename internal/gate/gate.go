// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package gate evaluates a verification record against a policy and writes
// the Cedar workload attribute result to .vet/gate-result.json.
// attest's Cedar PDP reads context.workload.* attributes from this file.
package gate

import (
	"fmt"
	"os"
	"time"

	"github.com/provabl/vet/internal/store"
	"gopkg.in/yaml.v3"
)

// Policy is the vet verification policy (.vet/policy.yaml).
type Policy struct {
	MinSLSALevel      int      `yaml:"min_slsa_level"`
	CVEThreshold      string   `yaml:"cve_threshold"` // "critical", "high", "medium", ""
	AllowedSigningIDs []string `yaml:"allowed_signing_ids,omitempty"`
}

// DefaultPolicy returns a sensible default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		MinSLSALevel: 0,
		CVEThreshold: "critical",
	}
}

// LoadPolicy reads a policy from the given path, or returns the default if not found.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path) // #nosec G304 — operator-controlled path
	if os.IsNotExist(err) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	return &p, yaml.Unmarshal(data, &p)
}

// Evaluator evaluates verification records against a policy.
type Evaluator struct {
	store  *store.Store
	policy *Policy
}

// New creates an Evaluator.
func New(s *store.Store, p *Policy) *Evaluator {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Evaluator{store: s, policy: p}
}

// EvaluateResult is the result of a gate evaluation.
type EvaluateResult struct {
	ArtifactRef  string
	ArtifactHash string
	PolicyMet    bool
	Failures     []string
	GateResult   *store.GateResult
}

// Evaluate looks up the verification record for artifactRef and evaluates it
// against the policy. Writes gate-result.json with Cedar workload attributes.
func (e *Evaluator) Evaluate(artifactRef string) (*EvaluateResult, error) {
	rec, err := e.store.LoadRecord(artifactRef)
	if err != nil {
		return nil, fmt.Errorf("load record: %w", err)
	}
	if rec == nil {
		return nil, fmt.Errorf("no verification record found for %q — run 'vet verify' first", artifactRef)
	}

	var failures []string

	if !rec.Signed {
		failures = append(failures, "artifact is not signed — run 'vet sign' first")
	}

	if e.policy.MinSLSALevel > 0 && rec.SLSALevel < e.policy.MinSLSALevel {
		failures = append(failures,
			fmt.Sprintf("SLSA level %d is below minimum %d", rec.SLSALevel, e.policy.MinSLSALevel))
	}

	switch e.policy.CVEThreshold {
	case "critical":
		if rec.CVECritical {
			failures = append(failures, "critical CVEs found in artifact SBOM")
		}
	case "high":
		if rec.CVECritical || rec.CVEHigh {
			failures = append(failures, "high or critical CVEs found in artifact SBOM")
		}
	}

	policyMet := len(failures) == 0

	gateResult := &store.GateResult{
		Artifact:     artifactRef,
		ArtifactHash: rec.ArtifactHash,
		SLSALevel:    rec.SLSALevel,
		SBOMPresent:  rec.SBOMPresent,
		CVECritical:  rec.CVECritical,
		CVEHigh:      rec.CVEHigh,
		Signed:       rec.Signed,
		PolicyMet:    policyMet,
		EvaluatedAt:  time.Now(),
	}

	if err := e.store.SaveGateResult(gateResult); err != nil {
		return nil, fmt.Errorf("save gate result: %w", err)
	}

	return &EvaluateResult{
		ArtifactRef:  artifactRef,
		ArtifactHash: rec.ArtifactHash,
		PolicyMet:    policyMet,
		Failures:     failures,
		GateResult:   gateResult,
	}, nil
}
