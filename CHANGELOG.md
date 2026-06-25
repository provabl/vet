# Changelog

All notable changes to vet will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`vet ami-scan` — deep AMI content scanning, end to end** (provabl/vet#32, slice 6): the CLI that
  ties the pipeline together. `vet ami-scan <ami-id> --helper-instance i-… --az … --scan-bucket …`
  resolves the AMI's backing snapshot, mounts a copy read-only on the operator's helper instance,
  syfts the filesystem, and stores the SBOM where `vet verify <ami-id> --check-cves <level>` reads it
  (AMIs auto-route to the distro-aware grype scanner). vet creates a volume + attachment and tears them
  down when done — never the helper instance, never the AMI's own snapshot. Arg/flag validation
  fake-tested. Closes the AMI deep-content-scan gap end to end — the last remaining item of the
  AMI-gating epic (provabl#13).

- **`amiscan` live AWS adapters — EC2 volumes + SSM/S3 remote syft** (provabl/vet#32, slice 5): the thin
  adapters behind the slice-4 seams. `ec2Volumes` (`VolumeManager`) makes the EC2
  `CreateVolume`(from snapshot, gp3, tagged `vet:ephemeral`) / `AttachVolume` / `DetachVolume` /
  `DeleteVolume` calls, each waiting on the right state transition (available → in-use → available)
  before the next step. `ssmScanner` (`RemoteScanner`) sends an `AWS-RunShellScript` that mounts the
  attached device **read-only** (`-o ro`, so the scan can't mutate the evidence), runs syft to a
  CycloneDX SBOM, and uploads it to an S3 staging bucket (S3 because a full-AMI SBOM exceeds SSM's
  inline output cap), then downloads it locally; it polls the command to a terminal state and surfaces
  remote stderr on failure. `amiscan.NewLive` assembles the whole live `Scanner` (inspector + volume
  manager + remote scanner). Adds the SSM + S3 SDKs. SSM-scanner lifecycle is fake-tested
  (success-downloads / remote-failure-surfaces-stderr / bucket-required / poll-timeout); the EC2 volume
  calls are thin waiter wrappers. The CLI `vet verify ami-… --deep-scan` wiring + live validation are
  the final slice.

- **`amiscan` live Mounter — volume lifecycle with guaranteed teardown** (provabl/vet#32, slice 4):
  the `Mounter` impl that turns a backing snapshot into a scannable filesystem — `CreateVolume(from
  snapshot) → Attach(to helper) → remote mount + syft → [Release] Detach + Delete`. Two scope choices
  keep teardown small and safe: vet **never creates/terminates the helper instance** (the operator
  supplies a running, SSM-managed, syft-equipped instance), so vet only ever creates a *volume + an
  attachment*; and vet **never touches the AMI's own backing snapshot** — it scans a fresh volume made
  *from* it and deletes the copy. The volume lifecycle and the remote scan are separate seams
  (`VolumeManager`, `RemoteScanner`) so the bug-prone part — **the volume is detached and deleted on
  every failure path** (create-fails / attach-fails / scan-fails / detach-errors-but-delete-still-runs)
  — is fully fake-tested without AWS. The thin live adapters (EC2 volume calls; SSM+S3 remote scan,
  S3 because a full-AMI SBOM exceeds SSM's inline output cap) + live validation are the final slice.

- **`internal/amiscan` — AMI content-scan orchestration** (provabl/vet#32, slice 3): an AMI's contents
  aren't directly scannable — you reach them through snapshot → volume → attach → mount → syft. This
  slice ships the **orchestration core** (resolve the AMI's backing EBS snapshot, drive the steps, and
  **guarantee teardown even on failure**) behind two seams: `ImageInspector` (read-only EC2
  `DescribeImages`, resolves the backing snapshot — root-device-preferred, first-EBS fallback) and
  `Mounter` (the live-only snapshot→filesystem→SBOM step). `Scan` returns an **SBOM path** (not a
  verdict) for the grype `cve.Source` to scan — keeping CVE matching in `internal/cve` and AWS plumbing
  here. Fully fake-tested incl. the leak-safety cases (a mount that yields no SBOM is still released;
  no mount → no release returned); the EC2 inspector's resolution validated read-only against a real
  AL2023 AMI. The live `Mounter` impl (EBS attach + mount + syft, with full resource teardown) is the
  next slice — it creates real resources, so it lands with live validation, not in CI.

- **`cve.GrypeSource` — distro-aware CVE scanning for AMIs** (provabl/vet#32, slice 2): a second
  `cve.Source` that scans the **SBOM document** with grype (anchore/grype), which is distro-advisory
  aware (matches Amazon Linux / RHEL / Debian packages against their security feeds, e.g. Amazon ALAS)
  — fixing the false-clean gap the live test found, where a naive OSV `Linux` query reports a distro
  AMI as clean. `vet verify` gains `--cve-source auto|osv|grype` (default `auto`): an `ami-…` target
  routes to grype, everything else to OSV; an explicit value overrides. The `cve.Source` interface now
  takes a `Target{Packages, SBOMPath}` — the second implementer revealed one input shape doesn't fit
  both: OSV queries `Packages`, grype consumes the full `SBOMPath` document (the package list drops the
  distro metadata grype needs). grype is **fail-closed**: a missing SBOM path, absent grype binary,
  non-zero exit, or unparseable output all deny rather than pass. New `result.CVECheckRan` so the CLI
  no longer prints "✓ No critical/high CVEs" when the check actually failed to run. The live AWS wiring
  (EBS-snapshot → syft) is the next slice; this slice is fully fake-tested (no AWS).

- **`internal/cve` — a pluggable CVE-scanning seam** (provabl/vet#32, slice 1): extracted CVE scanning
  behind a `cve.Source` interface (`Scan(ctx, []sbom.Package) (Verdict, error)`), with the existing
  per-package OSV query as the default `OSVSource`. The Verifier delegates to a configurable source
  (`WithCVESource`), defaulting to OSV — no behaviour change for container/binary SBOMs. This is the
  foundation for AMI deep-content scanning: a live both-source test (commented on vet#32) showed the
  two viable AMI sources have *different* sharp edges — Amazon Inspector (managed, ALAS-native, but
  billable + gated on a managed/agentless instance) vs. EBS-snapshot→syft→distro-matcher (self-contained,
  but a **naive OSV `Linux` query returns false-clean for Amazon Linux packages** because OSV's `Linux`
  ecosystem is upstream-kernel-scoped, not ALAS-aware) — so CVE scanning is now a strategy, not a
  hardcoded call. The OSV source honestly reports unresolvable (bare-name) packages as *scanned: 0*
  rather than passing them. Fail-closed preserved (a source that can't evaluate denies). The `inspector`
  and `snapshot+grype` AMI sources land in follow-up slices.

- **Added a `Security Scan` workflow** (`.github/workflows/security.yml`): govulncheck + Trivy filesystem (dependency) + Trivy IaC scans on every push/PR and weekly, blocking on HIGH/CRITICAL. Trivy pinned to `v0.36.0`. Brings this repo in line with the rest of the suite — every Provabl tool now self-scans, fitting a security/compliance suite.
- **`vet ami-reference`** (provabl#13): records a vetted AMI's known-good boot measurements as locked
  `attest:pcr<N>` tags (`--pcr <index>=<hex>`, repeatable), so a running instance can be bound to the
  vetted image — the kernel appraisers already check `expected_pcr<N>`. NitroTPM/enclave PCRs can't be
  computed offline, so the values come from a trusted reference boot's `.nitro`/`.tpm` attestation
  output (runbook in README). The tags are locked to the vetter by ground's lockdown SCP. Index/hex
  validated; written via the existing EC2 tagger.
- **`vet preflight`** (provabl#16): verifies the calling principal holds the IAM action vet's AMI
  vetter needs (`ec2:CreateTags`) via read-only `iam:SimulatePrincipalPolicy` against the caller ARN.
  Renders ✓/✗ per action with remediation; exits non-zero on any deny; fail-closed on an un-callable
  check. New `internal/preflight` (mock-driven tests). Mirrors attest/ground; each suite tool carries
  its own copy (the kernel is the only shared dep). See `docs/required-permissions.md`.
- **AMI vetting** (provabl#13, slice 2): `vet gate ami-… --tag-vetted` writes the `attest:vetted=true`
  tag to an AWS AMI via the EC2 API when the gate passes — the producer for ground's AMI-launch-gating
  SCP (which permits `ec2:RunInstances` only for AMIs carrying that tag). Fail-closed: a failing gate
  writes no tag. New `internal/amitag` (an injectable `Tagger` seam; AWS EC2 `CreateTags` in
  production, a fake in tests), the `ami-` target branch, and `--tag-vetted`/`--region` flags. Adds
  the AWS SDK (`aws-sdk-go-v2`, `service/ec2`). v1 asserts provenance/verdict + an authenticated
  vetter marking; deep AMI-content scanning and the runtime golden-PCR0 binding are deferred (see
  README + provabl#13). Validated by writing the tag to a real AMI.

### Changed

- **CI/release actions bumped to Node-24 runtimes**: `actions/checkout@v4→v6`,
  `actions/setup-go@v5→v6`, `softprops/action-gh-release@v2→v3` — clears the GitHub Node-20
  deprecation warnings for the actions we control. (Warnings from the slsa-github-generator's
  internal actions are upstream and clear when it ships past v2.1.0.)

### Fixed

- **`RELEASING.md` verification steps**: the provenance file is `multiple.intoto.jsonl` (one file
  for all binaries), not a per-binary `.intoto.jsonl`; and `gh attestation verify` does not work
  for the generic generator's release-asset provenance (404) — `slsa-verifier verify-artifact` is
  the correct consumer check. Verified against the v0.2.0 release.

## [0.2.0] - 2026-06-09

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

[Unreleased]: https://github.com/provabl/vet/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/provabl/vet/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/provabl/vet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/provabl/vet/releases/tag/v0.1.0
