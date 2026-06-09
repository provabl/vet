// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package gate evaluates a verification record against a policy and writes
// the Cedar workload attribute result to .vet/gate-result.json.
// attest's Cedar PDP reads context.workload.* attributes from this file.
package gate

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	"github.com/provabl/evidence/term"
	"gopkg.in/yaml.v3"

	vetasp "github.com/provabl/vet/internal/evidence"
	"github.com/provabl/vet/internal/store"
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
	ArtifactRef   string
	ArtifactHash  string
	PolicyMet     bool
	MissingRecord bool // true when no prior 'vet verify' record exists
	Failures      []string
	GateResult    *store.GateResult
}

// Evaluate looks up the verification record for artifactRef and evaluates it
// against the policy, producing the verdict THROUGH the provabl/evidence kernel:
// it runs the canonical Copland term Seq(Nonce, Seq(Meas, Sig)) through the CVM,
// appraises the resulting evidence bundle, and lowers the verdict to the Cedar
// workload attributes written to gate-result.json. The judgment is no longer
// hand-rolled here — it lives in vet's (ASP, appraiser) pair (internal/evidence).
//
// If no verification record exists (vet verify was never run for this artifact),
// the measurer returns a CollectFailed measurement; appraisal fails the spine of
// claims, and Evaluate writes a fail-closed gate result (PolicyMet=false, all
// attributes false/0) with MissingRecord=true so the caller can print guidance.
func (e *Evaluator) Evaluate(ctx context.Context, artifactRef string) (*EvaluateResult, error) {
	reg := asp.NewRegistry()
	if err := reg.Register(vetasp.Provider(vetasp.StoreSource{Store: e.store})); err != nil {
		return nil, fmt.Errorf("register vet provider: %w", err)
	}
	am, err := vetasp.NewEphemeralAM()
	if err != nil {
		return nil, err
	}
	c := cvm.New(reg, am, am, nil)

	// Policy values flow to the appraiser through the term's params, so the
	// kernel — not gate — applies them.
	params := term.Params{}
	if e.policy.MinSLSALevel > 0 {
		params["min_slsa_level"] = strconv.Itoa(e.policy.MinSLSALevel)
	}
	if e.policy.CVEThreshold != "" {
		params["cve_threshold"] = e.policy.CVEThreshold
	}
	protocol := term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, vetasp.ID, vetasp.Target(artifactRef), params),
			term.Sig(),
		),
	)

	bundle, ch, err := c.Run(ctx, protocol)
	if err != nil {
		return nil, fmt.Errorf("run attestation: %w", err)
	}
	verdict, err := c.Appraise(ctx, bundle, ch)
	if err != nil {
		return nil, fmt.Errorf("appraise: %w", err)
	}

	attrs := lower.ToAttributes(verdict)
	missingRecord := isMissingRecord(verdict)
	gateResult := gateResultFromAttrs(artifactRef, attrs, verdict.Pass)

	// Best-effort on the missing-record path (don't mask a real save error
	// otherwise), matching prior behavior.
	if missingRecord {
		_ = e.store.SaveGateResult(gateResult)
	} else if err := e.store.SaveGateResult(gateResult); err != nil {
		return nil, fmt.Errorf("save gate result: %w", err)
	}

	failures := failuresFromVerdict(verdict)
	if missingRecord {
		failures = []string{"no verification record — run 'vet verify <artifact>' before 'vet gate'"}
	}

	return &EvaluateResult{
		ArtifactRef:   artifactRef,
		ArtifactHash:  gateResult.ArtifactHash,
		PolicyMet:     verdict.Pass,
		MissingRecord: missingRecord,
		Failures:      failures,
		GateResult:    gateResult,
	}, nil
}

// isMissingRecord reports whether the bundle's only finding was that the
// measurement could not be taken (CollectFailed) — surfaced by the kernel as a
// "<asp>.collected=false" claim and the absence of any workload.* claim.
func isMissingRecord(v asp.Verdict) bool {
	for _, c := range v.Claims {
		if c.Key == string(vetasp.ID)+".collected" && c.Value == "false" {
			return true
		}
	}
	return false
}

// failuresFromVerdict reconstructs the bulleted failure list the CLI prints from
// the structured failure claims the appraiser emitted (not by splitting Reason).
func failuresFromVerdict(v asp.Verdict) []string {
	var out []string
	for _, c := range v.Claims {
		if c.Key == vetasp.ClaimFailure {
			out = append(out, c.Value)
		}
	}
	return out
}

// gateResultFromAttrs is the single chokepoint mapping lowered Cedar attributes
// back to the store.GateResult contract. Absent workload.* attributes (the
// CollectFailed / missing-record case) default to zero/false, exactly
// reproducing the prior fail-closed result.
func gateResultFromAttrs(artifactRef string, attrs map[string]lower.Attr, policyMet bool) *store.GateResult {
	return &store.GateResult{
		Artifact:     artifactRef,
		ArtifactHash: attrs[vetasp.ClaimArtifactHash].Value,
		SLSALevel:    attrInt(attrs, vetasp.ClaimSLSALevel),
		SBOMPresent:  attrBool(attrs, vetasp.ClaimSBOMPresent),
		CVECritical:  attrBool(attrs, vetasp.ClaimCVECritical),
		CVEHigh:      attrBool(attrs, vetasp.ClaimCVEHigh),
		Signed:       attrBool(attrs, vetasp.ClaimSigned),
		PolicyMet:    policyMet,
		EvaluatedAt:  time.Now(),
	}
}

func attrBool(attrs map[string]lower.Attr, key string) bool {
	return attrs[key].Value == "true"
}

func attrInt(attrs map[string]lower.Attr, key string) int {
	n, _ := strconv.Atoi(attrs[key].Value)
	return n
}
