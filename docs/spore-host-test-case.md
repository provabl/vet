# spore.host Reference Test Case

spore.host ([github.com/scttfrdmn/mycelium](https://github.com/scttfrdmn/mycelium)) is the
vet reference test case. It exercises the hardest supply chain scenarios:
a binary that runs on a user's laptop, deploys EC2 instances into an AWS account,
uses images from another account, and needs a compliant SRE-resident variant.

---

## Scenario 1: Verify a local binary

The `spawn` binary runs on the user's laptop. Before it can assume an IAM role
in a CUI SRE, vet verifies its SLSA provenance from the GitHub Actions release pipeline.

```bash
# Download the spawn binary from a GitHub release
curl -Lo ~/bin/spawn https://github.com/scttfrdmn/mycelium/releases/latest/download/spawn_linux_amd64
chmod +x ~/bin/spawn

# Verify SLSA provenance (requires gh CLI authenticated)
vet verify ~/bin/spawn \
  --source github.com/scttfrdmn/mycelium \
  --min-slsa-level 2

# Expected output:
#   ✓ Signed — https://github.com/scttfrdmn/mycelium/.github/workflows/release.yml
#   ✓ SLSA Level 2 provenance verified
#   ✓ spawn verified
```

If the binary was modified after signing, `vet verify` exits 1.

---

## Scenario 2: Cross-account AMI trust

spore.host launches EC2 instances using AMIs that may originate from a different
AWS account (e.g., a shared AMI catalog or marketplace). vet verifies the AMI
owner is in an approved allowlist and has no critical CVEs in base packages.

```bash
# Find the AMI ID used by a running spore.host instance
AMI_ID=$(aws ec2 describe-instances --instance-ids i-0abc123 \
  --query 'Reservations[0].Instances[0].ImageId' --output text)

# Verify the AMI source (owner allowlist is configured in .vet/policy.yaml)
vet verify "ami:$AMI_ID" \
  --type ami \
  --check-cves critical

# .vet/policy.yaml for AMI verification:
# allowed_ami_owner_ids:
#   - "123456789012"   # your institution's AMI catalog account
#   - "amazon"        # AWS-managed AMIs
```

**Note:** AMI provenance is weaker than container image provenance — no SLSA chain.
vet documents AMI as Level 1 (source attributable, not build-provenance verified).

---

## Scenario 3: Laptop → SRE trust boundary

For CUI environments, an unverified local binary calling SRE APIs is a compliance
gap. ground deploys a `vet:slsa-level` IAM trust policy condition. vet gate writes
the workload attributes that satisfy that condition.

```bash
# After verifying spawn (Scenario 1), gate it for SRE access
vet gate ~/bin/spawn --policy .vet/policy.yaml

# Expected output:
#   Gate evaluation: /home/user/bin/spawn
#   context.workload.SLSALevel    = 2
#   context.workload.SBOMPresent  = false
#   context.workload.CVECritical  = false
#   context.workload.Signed       = true
#   ✓ Policy met — Cedar attributes written to .vet/gate-result.json

# ground deploys this IAM trust policy condition on the researcher role:
# "Condition": {
#   "StringGreaterThanOrEquals": {
#     "aws:PrincipalTag/vet:slsa-level": "2"
#   }
# }
```

The IAM role won't be assumable by spawn unless `vet gate` has been run and the
`vet:slsa-level` tag is set to 2 or higher on the session.

---

## Scenario 4: SRE-resident compliant mode

For the most sensitive environments, spore.host runs as a container inside the SRE
rather than on the user's laptop. This is the reference implementation of a
fully vet-certified workload.

```bash
# Build the SRE-resident spawn container
docker build -t ghcr.io/scttfrdmn/spawn-sre:v1.4.0 .

# Full vet pipeline: sign → verify → sbom → gate
vet sign ghcr.io/scttfrdmn/spawn-sre:v1.4.0 --yes
vet sbom ghcr.io/scttfrdmn/spawn-sre:v1.4.0 --format spdx --attest
vet verify ghcr.io/scttfrdmn/spawn-sre:v1.4.0 \
  --source github.com/scttfrdmn/mycelium \
  --min-slsa-level 2 \
  --check-cves critical
vet gate ghcr.io/scttfrdmn/spawn-sre:v1.4.0

# Verify Cedar attributes are written
cat .vet/gate-result.json
# {
#   "artifact": "ghcr.io/scttfrdmn/spawn-sre:v1.4.0",
#   "slsa_level": 2,
#   "sbom_present": true,
#   "cve_critical": false,
#   "signed": true,
#   "policy_met": true
# }
```

The SRE-resident container can now be deployed inside the SRE. The Cedar policy
in attest grants it access based on `context.workload.*` attributes.

---

## .vet/policy.yaml for spore.host

```yaml
# Minimum requirements for spore.host in a research SRE
min_slsa_level: 2
cve_threshold: "critical"
allowed_signing_ids:
  - "https://github.com/scttfrdmn/mycelium/.github/workflows/release.yml"
```

---

## Running the integration tests

```bash
# Prerequisites: cosign, gh CLI, syft installed
# Authentication: gh auth login, AWS credentials configured

cd ~/src/spore-host

# Run all 4 scenarios
bash test/integration/spore_host_scenarios.sh
```
