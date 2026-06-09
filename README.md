# vet

**Software supply chain verification for AWS Secure Research Environments**

Part of the [Provabl](https://provabl.dev) suite:
- **[ground](https://ground.provabl.dev)** — deploy correct AWS foundations
- **[attest](https://attest.provabl.dev)** — compile, enforce, and prove compliance
- **[qualify](https://qualify.provabl.dev)** — train and qualify researchers
- **vet** — vet your software ← you are here

> Ground your infrastructure, attest your controls, qualify your people, vet your software.

---

## What vet does

vet verifies software artifacts before they are permitted to access sensitive data in
an SRE. Where qualify qualifies the *person*, vet qualifies the *software*.

```bash
vet sign    image:tag            # sign artifact via Sigstore keyless
vet verify  image:tag            # verify SLSA provenance + CVE status
vet sbom    image:tag --attest   # generate and attest SBOM
vet gate    image:tag            # write Cedar workload attributes for attest
```

## Required external tools

vet shells out to standard supply-chain tools; each is needed only for the checks that use it:

| Tool | Used by | Needed for |
|---|---|---|
| [cosign](https://github.com/sigstore/cosign) | `vet sign`, `vet verify`, `vet sbom --attest` | Sigstore keyless signing + signature verification |
| [`gh`](https://cli.github.com) | `vet verify --source` | SLSA provenance (`gh attestation verify`) |
| [syft](https://github.com/anchore/syft#installation) | `vet sbom` | SBOM generation (SPDX / CycloneDX) |

CVEs are queried from the [OSV API](https://osv.dev) over HTTPS (no local tool) using the packages
parsed from a stored SBOM. **vet fails closed**: if a requested check's tool or input is missing —
`--source` without `gh`, or `--check-cves` without an SBOM — verify reports a policy violation
rather than silently passing.

## Status

🚧 **Under active development** — initial CLI being built.

## Open source

vet is fully open source (Apache 2.0) with no commercial tier. It integrates with [attest](https://attest.provabl.dev) by writing Cedar workload attributes that the attest Cedar PDP evaluates. See [COMMERCIAL.md](COMMERCIAL.md).

## License

Apache 2.0. Copyright 2026 Playground Logic LLC.
