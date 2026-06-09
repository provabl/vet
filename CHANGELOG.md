# Changelog

All notable changes to vet will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Verdict produced through the provabl/evidence kernel** (#9): `vet gate` now appraises via the
  evidence kernel `(ASP, appraiser)` pair (`internal/evidence`) and lowers to the
  `context.workload.*` attributes, instead of hand-rolled checks. Ephemeral per-run AM key.
- **Real SBOM parsing** (`internal/sbom/parse.go`, #15): parse syft's SPDX-JSON and CycloneDX-JSON
  into a package list (prefers PURL, derives the OSV ecosystem). `SBOMPresent` now means "a valid
  SBOM with ≥1 package", not merely a file on disk.
- **Real CVE checking** (#13): `vet verify --check-cves` parses the SBOM and queries OSV
  (`/v1/query`, severity inline) per package, setting CVECritical/CVEHigh from real data. **Fail
  closed**: a requested CVE gate that cannot run (no SBOM / unparseable / OSV unreachable) is a
  policy violation, never a silent pass. (Was a no-op that silently passed vulnerable artifacts.)
- **Required external tools** documented (cosign / gh / syft) in `vet verify` help and the README.

### Changed

- **Release provenance upgraded to SLSA Level 3** (provabl#5): `release.yml` now generates
  provenance via the `slsa-framework/slsa-github-generator` reusable workflow (an isolated,
  non-falsifiable builder that signs the provenance itself) instead of
  `actions/attest-build-provenance` (L2, same-job). The build matrix collapses to one runner
  emitting a combined `hashes` output the generator consumes; cosign keyless signatures and the
  attested SBOM are retained. vet is the suite's L3 pilot. See `RELEASING.md` for verification
  (`slsa-verifier verify-artifact`); the L3 proof is produced on the next tagged release.
- **SLSA level derived structurally** (#14): replace the regex that matched a non-existent "slsa
  level" field (and always fell back to a hardcoded L2) with structural parsing of
  `gh attestation verify --format json` — verified `slsa.dev/provenance/v1` → L2;
  `slsa-github-generator` builder → L3; otherwise 0.
- **Missing `gh` surfaced distinctly** (#16): a missing `gh` CLI is reported as such (and fails
  closed under `--min-slsa-level`) rather than silently reporting level 0.
- **`SBOMPresent`/`ArtifactHash` populated** on the verification record (#10) — previously always
  false/empty, so the kernel-routed gate's claims could never reflect reality.
- Copyright holder normalized to Playground Logic LLC.

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
