// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package cve defines the pluggable CVE-scanning seam: a Source takes the
// packages identified for an artifact and returns whether any have known
// critical/high vulnerabilities. The default Source queries OSV per package
// (the path vet has always used for container/binary SBOMs).
//
// The seam exists because an AMI is a different scanning problem than a language
// artifact, and a live both-source test (provabl/vet#32) showed the two viable
// AMI sources have different sharp edges:
//   - Amazon Inspector — managed, ALAS-native, but billable and gated on the
//     instance being Inspector-managed (or agentless EBS-snapshot scanning).
//   - EBS snapshot → syft → a distro-aware matcher — self-contained, on-demand,
//     but a NAIVE OSV "Linux" query returns false-clean for Amazon Linux packages
//     (OSV's Linux ecosystem is upstream-kernel-scoped, not ALAS-aware).
//
// So CVE scanning is a strategy, not a hardcoded call. This package is the
// interface + the default OSV Source; the AMI sources (inspector, snapshot+grype)
// register as additional Sources in their own slices.
package cve

import (
	"context"

	"github.com/provabl/vet/internal/sbom"
)

// Verdict is the outcome of a CVE scan: whether any scanned package carries a
// known critical/high vulnerability. It is intentionally coarse — it matches the
// CVECritical/CVEHigh booleans the gate and the context.workload.* contract use.
// Scanned reports how many packages were actually evaluated, so a caller can tell
// a genuine clean result from one where nothing was checked.
type Verdict struct {
	Critical bool
	High     bool
	Scanned  int
}

// Source scans the given packages for known vulnerabilities. A Source must
// fail closed: if it cannot evaluate the packages (database unreachable, an
// ecosystem it cannot resolve when the caller demanded a verdict), it returns a
// non-nil error rather than a falsely-clean Verdict. Returning a clean Verdict
// means "evaluated, and nothing critical/high was found."
//
// pkgs is the identified package set for the artifact (from an SBOM, or — for an
// AMI source — enumerated off the image). The Source decides how to match them to
// advisories; that matching is the whole point of the seam.
type Source interface {
	// Name identifies the source for logs and records, e.g. "osv".
	Name() string
	// Scan evaluates pkgs and returns the critical/high verdict.
	Scan(ctx context.Context, pkgs []sbom.Package) (Verdict, error)
}
