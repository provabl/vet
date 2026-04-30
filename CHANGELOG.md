# Changelog

All notable changes to vet will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-30

### Fixed

- **`vet gate` pre-verify guidance**: when no verification record exists (i.e., `vet verify` was never run), `gate` now writes a fail-closed `gate-result.json` (all attributes false/0, `PolicyMet=false`) and prints an actionable warning to stderr: `warning: no verification record found — Run 'vet verify <artifact>' first`. Previously returned a bare error with no gate-result.json written, leaving CI pipelines without the artifact they expected.

### Security

- **Artifact ref flag injection**: `vet sign` and `vet verify` now reject artifact refs starting with `-`, preventing flag-like strings from being misinterpreted by cosign or gh CLI.

## [0.1.0] - 2026-04-29

### Added

- **`vet sign <artifact>`**: keyless cosign signing via Sigstore. Container images signed with `cosign sign`; local files with `cosign sign-blob`. Writes `.vet/records/<hash>.json` with signing result and Rekor log ID.
- **`vet verify <artifact>`**: signature verification via `cosign verify-blob`; SLSA provenance via `gh attestation verify`; CVE check via OSV API. Writes verification record to `.vet/records/`.
- **`vet sbom <artifact>`**: SBOM generation via `syft`, optional attestation via `cosign attest --predicate`. Writes SBOM to `.vet/sboms/`.
- **`vet gate <artifact>`**: reads verification record and evaluates against `.vet/policy.yaml` (min SLSA level, CVE threshold). Writes `.vet/gate-result.json` with Cedar workload attribute names matching `context.workload.SLSALevel`, `context.workload.Signed`, etc. for attest PDP consumption.
- **`internal/store/`**: `.vet/` directory management — `VerificationRecord`, `GateResult`, record and SBOM path helpers.
- **Policy**: `MinSLSALevel`, `CVEThreshold` (critical/high/medium), `AllowedSigningIDs`. Default policy: `CVEThreshold: critical`.
- **SLSA Level 2 release workflow**: `actions/attest-build-provenance` + cosign keyless + SBOM.
- **`vet.provabl.dev`** documentation site (GitHub Pages).
- Test coverage: sign, verify, store, gate with mock runner interface.

[Unreleased]: https://github.com/provabl/vet/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/provabl/vet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/provabl/vet/releases/tag/v0.1.0
