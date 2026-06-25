// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"errors"
	"fmt"
)

// The live Mounter materialises a snapshot's filesystem on an operator-provided
// helper instance and runs syft over it. The lifecycle is:
//
//	CreateVolume(from snapshot, in the helper's AZ) -> AttachVolume(to helper) ->
//	remote: mount read-only + syft -> download SBOM -> [Release] Detach + Delete.
//
// Two deliberate scope choices keep teardown small and safe:
//   - vet does NOT create or terminate the helper instance. The operator supplies a
//     running, SSM-managed, syft-equipped instance (Config.InstanceID). So vet only
//     ever creates a volume + an attachment — never an instance.
//   - vet never touches the AMI's own backing snapshot; it creates a NEW volume
//     FROM that snapshot, scans the copy, and deletes the copy.
//
// The volume lifecycle and the remote scan are separate seams so the bug-prone
// part — guaranteeing the volume is detached and deleted on every path — is fully
// fake-testable without AWS. The live adapters (EC2 + SSM/S3) are thin.

// VolumeManager owns the EBS volume lifecycle for one scan.
type VolumeManager interface {
	// CreateFromSnapshot creates a volume from snapshotID in the given AZ and
	// returns its id once it is available for attachment.
	CreateFromSnapshot(ctx context.Context, snapshotID, az string) (volumeID string, err error)
	// Attach attaches volumeID to instanceID at device (e.g. "/dev/sdf") and
	// returns once attached.
	Attach(ctx context.Context, volumeID, instanceID, device string) error
	// Detach detaches volumeID and returns once detached.
	Detach(ctx context.Context, volumeID string) error
	// Delete deletes volumeID.
	Delete(ctx context.Context, volumeID string) error
}

// RemoteScanner mounts an attached device on the helper instance read-only, runs
// syft over its filesystem, and returns a LOCAL path to the downloaded SBOM. It
// wraps SSM (run the commands) + S3 (ferry the SBOM back, since a full-AMI SBOM
// exceeds SSM's inline output cap). It unmounts on its own; it does not own the
// volume (the VolumeManager does).
type RemoteScanner interface {
	Scan(ctx context.Context, instanceID, device string) (sbomPath string, err error)
}

// Config is the operator-supplied context the live Mounter needs.
type Config struct {
	InstanceID string // a running, SSM-managed, syft-equipped helper instance
	AZ         string // the helper instance's availability zone (volume must match)
	Device     string // device name to attach at, e.g. "/dev/sdf"
}

// ssmMounter is the live Mounter: it composes a VolumeManager + a RemoteScanner.
type ssmMounter struct {
	vols VolumeManager
	scan RemoteScanner
	cfg  Config
}

// NewMounter builds a live Mounter from the volume + remote-scan seams and config.
// Exposed with injectable seams so the lifecycle is testable; the production
// wiring (EC2 VolumeManager + SSM/S3 RemoteScanner) is assembled by the caller.
func NewMounter(vols VolumeManager, scan RemoteScanner, cfg Config) Mounter {
	return &ssmMounter{vols: vols, scan: scan, cfg: cfg}
}

// Mount creates a volume from the snapshot, attaches it to the helper instance,
// runs the remote scan, and returns a Mount whose Release detaches + deletes the
// volume. Teardown is guaranteed on every failure path: if attach or the remote
// scan fails after the volume exists, the volume is detached (best-effort) and
// deleted before returning, so a failed scan never leaks an EBS volume.
func (m *ssmMounter) Mount(ctx context.Context, snapshotID string) (*Mount, error) {
	if m.cfg.InstanceID == "" || m.cfg.AZ == "" || m.cfg.Device == "" {
		return nil, fmt.Errorf("mounter config incomplete: need InstanceID, AZ, and Device")
	}

	volID, err := m.vols.CreateFromSnapshot(ctx, snapshotID, m.cfg.AZ)
	if err != nil {
		return nil, fmt.Errorf("create volume from %s: %w", snapshotID, err)
	}
	// From here on, the volume exists — every error path must delete it.

	if err := m.vols.Attach(ctx, volID, m.cfg.InstanceID, m.cfg.Device); err != nil {
		// Not attached: just delete the volume.
		m.cleanup(ctx, volID, false)
		return nil, fmt.Errorf("attach volume %s to %s: %w", volID, m.cfg.InstanceID, err)
	}

	sbomPath, err := m.scan.Scan(ctx, m.cfg.InstanceID, m.cfg.Device)
	if err != nil {
		// Attached but scan failed: detach then delete.
		m.cleanup(ctx, volID, true)
		return nil, fmt.Errorf("remote scan of %s on %s: %w", volID, m.cfg.InstanceID, err)
	}

	return &Mount{
		SBOMPath: sbomPath,
		Release: func(ctx context.Context) error {
			return m.cleanup(ctx, volID, true)
		},
	}, nil
}

// cleanup detaches (when attached) and deletes the volume. Both steps are attempted
// even if one errors, so a detach failure cannot strand a deletable volume; the
// combined error is returned for the caller to surface/log.
func (m *ssmMounter) cleanup(ctx context.Context, volID string, attached bool) error {
	var errs []error
	if attached {
		if err := m.vols.Detach(ctx, volID); err != nil {
			errs = append(errs, fmt.Errorf("detach %s: %w", volID, err))
		}
	}
	if err := m.vols.Delete(ctx, volID); err != nil {
		errs = append(errs, fmt.Errorf("delete %s: %w", volID, err))
	}
	return errors.Join(errs...)
}
