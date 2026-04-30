# vet — Project Rules

## Overview

vet is the software supply chain layer of the Provabl suite.
It verifies software artifacts before they can access sensitive data in an SRE.

**Tagline**: ground your infrastructure, attest your controls, qualify your people, vet your software.

## What vet does

```
vet sign    → sign artifacts via Sigstore keyless (cosign)
vet verify  → verify SLSA provenance, CVE status, SBOM presence
vet sbom    → generate and attest SBOM (SPDX/CycloneDX via syft)
vet gate    → write Cedar workload attributes (SLSALevel, SBOMPresent, CVECritical)
             for attest's Cedar PDP to evaluate
```

## Integration with attest

vet writes to a `.vet/` directory alongside `.attest/`. Cedar policies in attest
can require workload verification before granting access to CUI/PHI data:

```cedar
permit(principal, action, resource in ResourceGroup::"cui-data")
when {
  principal.CUITrainingCurrent == true &&   // from qualify
  context.workload.SLSALevel >= 2 &&        // from vet
  context.workload.CVECritical == false      // from vet
};
```

## Versioning

- Semantic Versioning 2.0.0
- Tag releases as vMAJOR.MINOR.PATCH
- CHANGELOG.md following keepachangelog 1.1.0

## Go Conventions

- Go 1.26+
- Module path: github.com/provabl/vet
- No init() functions. No global mutable state.
- Errors returned, not logged-and-continued.
- go vet ./... and go test ./... before committing.

## Architecture

```
vet/
├── cmd/vet/          — CLI entry point
├── internal/
│   ├── sign/         — cosign + Sigstore signing
│   ├── provenance/   — SLSA provenance generation + verification
│   ├── sbom/         — SBOM generation (syft) + attestation
│   ├── verify/       — composite verification policy enforcement
│   ├── cedar/        — Cedar workload attribute writing for attest
│   └── store/        — .vet/ record storage
└── docs/
```
