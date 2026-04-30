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

## Status

🚧 **Under active development** — initial CLI being built.

## License

Apache 2.0
