// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeVols records the volume lifecycle calls so tests can assert teardown
// happened (and in the right order). Each step can be made to fail.
type fakeVols struct {
	createErr, attachErr, detachErr, deleteErr error
	calls                                      []string
}

func (f *fakeVols) CreateFromSnapshot(_ context.Context, snap, az string) (string, error) {
	f.calls = append(f.calls, "create")
	if f.createErr != nil {
		return "", f.createErr
	}
	return "vol-123", nil
}
func (f *fakeVols) Attach(_ context.Context, vol, inst, dev string) error {
	f.calls = append(f.calls, "attach")
	return f.attachErr
}
func (f *fakeVols) Detach(_ context.Context, vol string) error {
	f.calls = append(f.calls, "detach")
	return f.detachErr
}
func (f *fakeVols) Delete(_ context.Context, vol string) error {
	f.calls = append(f.calls, "delete")
	return f.deleteErr
}

type fakeScan struct {
	path string
	err  error
}

func (f fakeScan) Scan(context.Context, string, string) (string, error) {
	return f.path, f.err
}

func goodCfg() Config { return Config{InstanceID: "i-helper", AZ: "us-east-1a", Device: "/dev/sdf"} }

func TestMounter_HappyPathReleasesVolume(t *testing.T) {
	vols := &fakeVols{}
	m := NewMounter(vols, fakeScan{path: "/tmp/ami.sbom.json"}, goodCfg())

	mount, err := m.Mount(context.Background(), "snap-1")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if mount.SBOMPath != "/tmp/ami.sbom.json" {
		t.Errorf("sbom path = %q", mount.SBOMPath)
	}
	// Volume created + attached; not yet torn down.
	if got := strings.Join(vols.calls, ","); got != "create,attach" {
		t.Fatalf("calls before release = %q, want create,attach", got)
	}
	if err := mount.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got := strings.Join(vols.calls, ","); got != "create,attach,detach,delete" {
		t.Errorf("calls after release = %q, want create,attach,detach,delete", got)
	}
}

func TestMounter_IncompleteConfigRejected(t *testing.T) {
	m := NewMounter(&fakeVols{}, fakeScan{path: "/x"}, Config{InstanceID: "i-1"}) // missing AZ/Device
	if _, err := m.Mount(context.Background(), "snap-1"); err == nil {
		t.Error("expected an error for incomplete config")
	}
}

// Create fails → no volume exists → nothing to tear down.
func TestMounter_CreateFailsNoLeak(t *testing.T) {
	vols := &fakeVols{createErr: errors.New("quota")}
	m := NewMounter(vols, fakeScan{path: "/x"}, goodCfg())
	if _, err := m.Mount(context.Background(), "snap-1"); err == nil {
		t.Error("expected create error")
	}
	if got := strings.Join(vols.calls, ","); got != "create" {
		t.Errorf("calls = %q, want create only (no volume to delete)", got)
	}
}

// Attach fails → volume exists but is not attached → delete only (no detach).
func TestMounter_AttachFailsDeletesVolume(t *testing.T) {
	vols := &fakeVols{attachErr: errors.New("device busy")}
	m := NewMounter(vols, fakeScan{path: "/x"}, goodCfg())
	if _, err := m.Mount(context.Background(), "snap-1"); err == nil {
		t.Error("expected attach error")
	}
	if got := strings.Join(vols.calls, ","); got != "create,attach,delete" {
		t.Errorf("calls = %q, want create,attach,delete (no detach — never attached)", got)
	}
}

// Scan fails after attach → must detach AND delete (no leak).
func TestMounter_ScanFailsDetachesAndDeletes(t *testing.T) {
	vols := &fakeVols{}
	m := NewMounter(vols, fakeScan{err: errors.New("syft crashed")}, goodCfg())
	if _, err := m.Mount(context.Background(), "snap-1"); err == nil {
		t.Error("expected scan error")
	}
	if got := strings.Join(vols.calls, ","); got != "create,attach,detach,delete" {
		t.Errorf("calls = %q, want create,attach,detach,delete", got)
	}
}

// A detach error during cleanup must NOT prevent the delete — both are attempted.
func TestMounter_DetachErrorStillDeletes(t *testing.T) {
	vols := &fakeVols{detachErr: errors.New("still detaching")}
	m := NewMounter(vols, fakeScan{err: errors.New("scan boom")}, goodCfg())
	_, _ = m.Mount(context.Background(), "snap-1")
	if got := strings.Join(vols.calls, ","); got != "create,attach,detach,delete" {
		t.Errorf("calls = %q — delete must be attempted even when detach errors", got)
	}
}

// End-to-end through the Scanner: an AMI -> backing snapshot -> live mounter,
// confirming the orchestrator's release drives the volume teardown.
func TestScanner_WithLiveMounter(t *testing.T) {
	vols := &fakeVols{}
	mounter := NewMounter(vols, fakeScan{path: "/tmp/s.json"}, goodCfg())
	s := New(fakeInspector{snap: "snap-9"}, mounter)

	path, release, err := s.Scan(context.Background(), "ami-0live")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if path != "/tmp/s.json" {
		t.Fatalf("unexpected sbom path: %q", path)
	}
	if release == nil {
		t.Fatal("expected a non-nil release")
	}
	if err := release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := strings.Join(vols.calls, ","); got != "create,attach,detach,delete" {
		t.Errorf("full lifecycle = %q", got)
	}
}
