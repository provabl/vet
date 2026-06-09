// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package vetasp is vet's (ASP, appraiser) pair for the provabl/evidence kernel.
// It is the first re-pointing in phase two of ADR 0001: the gate verdict is no
// longer computed by hand-rolled if-statements — it is produced by running a
// Copland term through the kernel's CVM and appraising the resulting evidence,
// then lowering the verdict to Cedar workload attributes.
//
// The pair lives in vet (not in evidence/providers) on purpose: the kernel's
// CLAUDE.md says a provider may live in its tool's repo, and the falsifiable
// invariant (no ASP-specific branch) constrains only the kernel packages
// (term, ev, trust, asp, cvm, lower) — providers are not kernel. Keeping the
// claim shape here, next to the store.GateResult it must feed, is what keeps
// vet's Cedar output contract authored in one place.
package vetasp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/ev"
	"github.com/provabl/evidence/term"

	"github.com/provabl/vet/internal/store"
)

// ID keys this pair in the kernel registry.
const ID term.ASPID = "vet"

// TargetScheme is the opaque scheme the kernel routes on; the artifact ref is
// carried after it. The kernel never parses past the scheme.
const TargetScheme = "artifact://"

// Target builds the kernel target for an artifact reference.
func Target(artifactRef string) term.Target { return term.Target(TargetScheme + artifactRef) }

// artifactRef recovers the artifact reference from a kernel target.
func artifactRef(t term.Target) string { return strings.TrimPrefix(string(t), TargetScheme) }

// RecordSource fetches the verification record for an artifact target. Injected
// so the provider tests with no store/filesystem. Returns (nil, nil) when no
// record exists — a fact about the world, not an error.
type RecordSource interface {
	Fetch(ctx context.Context, target term.Target) (*store.VerificationRecord, error)
}

// Provider assembles the vet pair from an injected record source.
func Provider(src RecordSource) asp.Provider {
	return asp.Provider{
		ID:        ID,
		Measurer:  measurer{src: src},
		Appraiser: appraiser{},
	}
}

// StoreSource is the production RecordSource: it reads the verification record
// from the .vet/ store.
type StoreSource struct{ Store *store.Store }

// Fetch loads the record for the artifact named by the target.
func (s StoreSource) Fetch(_ context.Context, t term.Target) (*store.VerificationRecord, error) {
	return s.Store.LoadRecord(artifactRef(t))
}

// --- measurer: gather, do not judge -----------------------------------------

type measurer struct{ src RecordSource }

func (m measurer) Measure(ctx context.Context, in asp.MeasureIn) (ev.Measurement, error) {
	rec, err := m.src.Fetch(ctx, in.Target)
	if err != nil {
		return ev.Measurement{}, fmt.Errorf("vet: fetch record: %w", err)
	}
	if rec == nil {
		// No verification record — a recorded fact, never a pass. This is the
		// kernel-native expression of gate's fail-closed path.
		return ev.Measurement{
			Status: ev.CollectFailed,
			Detail: fmt.Sprintf("no verification record for %s — run 'vet verify' first", artifactRef(in.Target)),
		}, nil
	}
	// vet does not bind in.Nonce: it has no native channel. Freshness rides the
	// kernel's outer SIG over Seq(Nonce, Meas) — the whole reason vet is first.
	payload, err := json.Marshal(rec)
	if err != nil {
		return ev.Measurement{}, fmt.Errorf("vet: marshal record: %w", err)
	}
	return ev.Measurement{Payload: payload, Status: ev.Collected}, nil
}

// --- appraiser: decode, judge, emit claims ----------------------------------

// Claim keys for the Cedar workload contract. These PascalCase names are the
// hard contract attest's Cedar PDP reads from gate-result.json (context.workload.*);
// they are pinned by a golden test so they cannot silently drift.
const (
	ClaimSLSALevel    = "workload.SLSALevel"
	ClaimSBOMPresent  = "workload.SBOMPresent"
	ClaimCVECritical  = "workload.CVECritical"
	ClaimCVEHigh      = "workload.CVEHigh"
	ClaimSigned       = "workload.Signed"
	ClaimArtifactHash = "workload.ArtifactHash"
	// ClaimFailure carries one human-readable policy failure. Repeated; the gate
	// reconstructs the bulleted Failures[] from these rather than splitting Reason.
	ClaimFailure = "workload.failure"
)

type appraiser struct{}

func (appraiser) Appraise(_ context.Context, in asp.AppraiseIn) (asp.Verdict, error) {
	var rec store.VerificationRecord
	if err := json.Unmarshal(in.Meas.Payload, &rec); err != nil {
		return asp.Verdict{}, fmt.Errorf("vet: decode record: %w", err)
	}

	// Workload claims — always emitted, regardless of pass/fail, so a policy can
	// read the posture even on a denial.
	claims := []asp.Claim{
		{Key: ClaimSLSALevel, Value: strconv.Itoa(rec.SLSALevel), Type: "long"},
		{Key: ClaimSBOMPresent, Value: boolStr(rec.SBOMPresent), Type: "bool"},
		{Key: ClaimCVECritical, Value: boolStr(rec.CVECritical), Type: "bool"},
		{Key: ClaimCVEHigh, Value: boolStr(rec.CVEHigh), Type: "bool"},
		{Key: ClaimSigned, Value: boolStr(rec.Signed), Type: "bool"},
		{Key: ClaimArtifactHash, Value: rec.ArtifactHash, Type: "string"},
	}

	// Judgment — mirrors the policy rules gate.go enforced before this re-point.
	var failures []string
	if !rec.Signed {
		failures = append(failures, "artifact is not signed — run 'vet sign' first")
	}
	if minLevel := atoiDefault(in.Params["min_slsa_level"], 0); minLevel > 0 && rec.SLSALevel < minLevel {
		failures = append(failures, fmt.Sprintf("SLSA level %d is below minimum %d", rec.SLSALevel, minLevel))
	}
	switch in.Params["cve_threshold"] {
	case "critical":
		if rec.CVECritical {
			failures = append(failures, "critical CVEs found in artifact SBOM")
		}
	case "high":
		if rec.CVECritical || rec.CVEHigh {
			failures = append(failures, "high or critical CVEs found in artifact SBOM")
		}
	}

	for _, f := range failures {
		claims = append(claims, asp.Claim{Key: ClaimFailure, Value: f, Type: "string"})
	}

	reason := "supply-chain provenance verified"
	if len(failures) > 0 {
		reason = strings.Join(failures, "; ")
	}
	return asp.Verdict{Pass: len(failures) == 0, Claims: claims, Reason: reason}, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
