// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package amiscan orchestrates deep-content scanning of an AWS AMI: it resolves
// the AMI's backing EBS snapshot, materialises that snapshot's filesystem, runs
// syft over it to produce an SBOM, and returns the SBOM path for a distro-aware
// CVE source (grype) to scan. It is the live-AWS half of provabl/vet#32.
//
// An AMI's contents are not directly scannable — you reach them through
// snapshot → volume → attach → mount. That lifecycle is bug-prone (every created
// resource must be torn down, even on failure) and inherently live-only (the
// mount cannot be meaningfully faked). So this package splits the problem:
//
//   - The ORCHESTRATION (resolve the snapshot, drive the steps, GUARANTEE
//     teardown) lives here and is fully fake-testable — it is where the bugs are.
//   - The two effectful steps are interfaces: ImageInspector (read-only EC2,
//     resolves the backing snapshot) and Mounter (the live snapshot→filesystem→
//     SBOM step). Production impls wire AWS; tests use fakes.
//
// Nothing here computes a verdict — Scan returns an SBOM path; the caller feeds it
// to a cve.Source (grype) exactly as for any other SBOM. This keeps the CVE
// strategy in one place (internal/cve) and the AWS plumbing in another.
package amiscan

import (
	"context"
	"fmt"
	"strings"
)

// ImageInspector resolves AMI metadata. Satisfied by the EC2 client in
// production (ec2:DescribeImages, read-only); faked in tests.
type ImageInspector interface {
	// BackingSnapshot returns the EBS snapshot id backing the AMI's root device.
	BackingSnapshot(ctx context.Context, amiID string) (string, error)
}

// Mount is a materialised, readable copy of a snapshot's filesystem plus the SBOM
// produced from it. Release tears down everything the Mounter created for it.
type Mount struct {
	// SBOMPath is the path to the SBOM document syft produced from the filesystem.
	SBOMPath string
	// Release tears down whatever the Mounter created (temp volume, attachment,
	// helper resources). It must be safe to call exactly once; the orchestrator
	// always calls it.
	Release func(context.Context) error
}

// Mounter materialises a snapshot's filesystem and produces an SBOM from it. This
// is the live-only step (snapshot → volume → attach → mount → syft); production
// wires AWS + syft, tests fake it. A Mounter must not leak resources: everything
// it creates is released via Mount.Release.
type Mounter interface {
	Mount(ctx context.Context, snapshotID string) (*Mount, error)
}

// Scanner orchestrates an AMI content scan end to end.
type Scanner struct {
	inspector ImageInspector
	mounter   Mounter
}

// New builds a Scanner from an inspector and a mounter.
func New(inspector ImageInspector, mounter Mounter) *Scanner {
	return &Scanner{inspector: inspector, mounter: mounter}
}

// NewLive assembles a Scanner wired to AWS: a read-only EC2 inspector and a live
// Mounter (EC2 volume lifecycle + SSM/S3 remote syft). cfg names the
// operator-provided helper instance; bucket is the S3 SBOM staging bucket;
// localDir is where the SBOM lands. This is the production constructor the CLI's
// deep-scan path uses; the seam-based New stays for tests and custom wiring.
func NewLive(ctx context.Context, region, bucket, localDir string, cfg Config) (*Scanner, error) {
	inspector, err := NewEC2Inspector(ctx, region)
	if err != nil {
		return nil, err
	}
	vols, err := NewEC2VolumeManager(ctx, region)
	if err != nil {
		return nil, err
	}
	scanner, err := NewSSMScanner(ctx, region, bucket, localDir)
	if err != nil {
		return nil, err
	}
	return New(inspector, NewMounter(vols, scanner, cfg)), nil
}

// Scan resolves the AMI's backing snapshot, mounts it, and returns the path to
// the SBOM syft produced — for a cve.Source to scan. The returned release tears
// down everything created for the scan; the caller MUST call it (typically
// deferred) once it has finished with the SBOM. On any failure before a mount is
// established, Scan tears down what it created and returns a nil release.
//
// Returning the SBOM path (not a verdict) keeps the CVE matching in internal/cve:
// the caller does `src.Scan(ctx, cve.Target{SBOMPath: path})` with a grype source.
func (s *Scanner) Scan(ctx context.Context, amiID string) (sbomPath string, release func(context.Context) error, err error) {
	if !strings.HasPrefix(amiID, "ami-") {
		return "", nil, fmt.Errorf("expected an AMI id (ami-...), got %q", amiID)
	}
	snap, err := s.inspector.BackingSnapshot(ctx, amiID)
	if err != nil {
		return "", nil, fmt.Errorf("resolve backing snapshot for %s: %w", amiID, err)
	}
	if snap == "" {
		return "", nil, fmt.Errorf("AMI %s has no backing EBS snapshot to scan", amiID)
	}
	mount, err := s.mounter.Mount(ctx, snap)
	if err != nil {
		return "", nil, fmt.Errorf("mount snapshot %s: %w", snap, err)
	}
	if mount == nil || mount.SBOMPath == "" {
		// Defensive: a Mounter that returns no SBOM but also no error. Tear down
		// whatever it may have created, and fail closed.
		if mount != nil && mount.Release != nil {
			_ = mount.Release(ctx)
		}
		return "", nil, fmt.Errorf("mounter produced no SBOM for snapshot %s", snap)
	}
	return mount.SBOMPath, mount.Release, nil
}
