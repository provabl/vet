# vet — required AWS permissions

`vet preflight` verifies the calling AWS principal holds these actions, using
read-only `iam:SimulatePrincipalPolicy` against the caller ARN (from
`sts:GetCallerIdentity`). It **evaluates, it never acts** — running preflight changes
nothing. A denied action prints a remediation and the command exits non-zero.

Most of vet needs **no AWS at all**. The software-verification flow — `vet sign`,
`vet verify`, `vet sbom`, and `vet gate` on a container/binary target — shells out to
cosign/`gh`/syft and queries the [OSV API](https://osv.dev) over HTTPS, reading and
writing only the local `.vet/` store. vet's one AWS-touching operation is the **AMI
vetter**, below.

| Action | Needed by | Status |
|--------|-----------|--------|
| `sts:GetCallerIdentity` | preflight itself (resolves the caller ARN to simulate) | live |
| `iam:SimulatePrincipalPolicy` | preflight itself (the permission self-check) | live |
| `ec2:CreateTags` | the AMI vetter — `vet gate ami-… --tag-vetted` writes `attest:vetted=true`, and `vet ami-reference ami-…` writes the golden `attest:pcr<N>` tags, to the AMI via the EC2 API | live |

## The AMI vetter is the only AWS path

`vet gate ami-… --tag-vetted` and `vet ami-reference ami-…` are the sole commands that
reach AWS, and they reach it through one action: `ec2:CreateTags`. On a passing gate,
`--tag-vetted` writes `attest:vetted=true` to the AMI — the tag
[ground](https://github.com/provabl/ground)'s launch-gating SCP requires to permit
`ec2:RunInstances`. `vet ami-reference` writes the known-good boot measurements as
`attest:pcr<N>` tags so a running instance can later be bound to the vetted image.

A companion ground lockdown SCP restricts who may set those tags to a designated
**vetter principal**, so the principal running these commands (vet's CI) must be that
vetter. On a failing gate, **no tag is written** (fail-closed), so an un-vetted AMI
stays un-launchable.

To scope a principal to only the software flow today (no AMI vetting), grant nothing —
sign/verify/sbom/gate on a container or binary need no AWS. To run preflight, grant
`sts:GetCallerIdentity` + `iam:SimulatePrincipalPolicy`. The AMI vetter additionally
needs `ec2:CreateTags` on the target images.

## Boundary

vet **asserts an artifact's provenance/verdict and marks an AMI vetted; it never
decides access** (attest does, via the Cedar PDP reading `context.workload.*`) and
**never launches or modifies instances** — it only writes the `attest:vetted` /
`attest:pcr<N>` tags that ground's SCPs gate `ec2:RunInstances` on. The marking is only
as strong as the vetter principal staying locked by ground's lockdown SCP. See the
[README](../README.md) and `attest/docs/integrations/vet.md`.
