// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"errors"
	"testing"
)

type fakeInspector struct {
	snap string
	err  error
}

func (f fakeInspector) BackingSnapshot(context.Context, string) (string, error) {
	return f.snap, f.err
}

type fakeMounter struct {
	mount    *Mount
	err      error
	mounted  string // snapshot id it was asked to mount
	released bool
}

func (f *fakeMounter) Mount(_ context.Context, snap string) (*Mount, error) {
	f.mounted = snap
	if f.err != nil {
		return nil, f.err
	}
	m := f.mount
	if m != nil && m.Release == nil {
		m.Release = func(context.Context) error { f.released = true; return nil }
	}
	return m, nil
}

func okMount(path string) *Mount { return &Mount{SBOMPath: path} }

func TestScan_HappyPath(t *testing.T) {
	m := &fakeMounter{mount: okMount("/tmp/ami.sbom.json")}
	s := New(fakeInspector{snap: "snap-123"}, m)

	path, release, err := s.Scan(context.Background(), "ami-0abc")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if path != "/tmp/ami.sbom.json" {
		t.Errorf("sbom path = %q", path)
	}
	if m.mounted != "snap-123" {
		t.Errorf("mounted %q, want snap-123 (the resolved backing snapshot)", m.mounted)
	}
	if release == nil {
		t.Fatal("expected a non-nil release to tear down the mount")
	}
	if err := release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if !m.released {
		t.Error("release did not tear the mount down")
	}
}

func TestScan_RejectsNonAMIRef(t *testing.T) {
	s := New(fakeInspector{snap: "snap-1"}, &fakeMounter{mount: okMount("/x")})
	if _, _, err := s.Scan(context.Background(), "ghcr.io/o/i:v1"); err == nil {
		t.Error("expected an error for a non-AMI ref")
	}
}

func TestScan_InspectorError(t *testing.T) {
	m := &fakeMounter{mount: okMount("/x")}
	s := New(fakeInspector{err: errors.New("describe boom")}, m)
	if _, _, err := s.Scan(context.Background(), "ami-0abc"); err == nil {
		t.Error("expected inspector error to propagate")
	}
	if m.mounted != "" {
		t.Error("must not attempt a mount when the snapshot cannot be resolved")
	}
}

func TestScan_NoBackingSnapshot(t *testing.T) {
	m := &fakeMounter{mount: okMount("/x")}
	s := New(fakeInspector{snap: ""}, m)
	if _, _, err := s.Scan(context.Background(), "ami-0abc"); err == nil {
		t.Error("expected an error when the AMI has no backing snapshot")
	}
	if m.mounted != "" {
		t.Error("must not mount when there is no snapshot")
	}
}

func TestScan_MountError(t *testing.T) {
	s := New(fakeInspector{snap: "snap-1"}, &fakeMounter{err: errors.New("attach failed")})
	_, release, err := s.Scan(context.Background(), "ami-0abc")
	if err == nil {
		t.Error("expected mount error to propagate")
	}
	if release != nil {
		t.Error("no release should be returned when no mount was established")
	}
}

// A Mounter that returns a mount with no SBOM (but no error) must fail closed AND
// still release whatever it created — the orchestrator must never leak.
func TestScan_MountWithoutSBOMReleasesAndFails(t *testing.T) {
	released := false
	bad := &Mount{SBOMPath: "", Release: func(context.Context) error { released = true; return nil }}
	s := New(fakeInspector{snap: "snap-1"}, &fakeMounter{mount: bad})

	_, release, err := s.Scan(context.Background(), "ami-0abc")
	if err == nil {
		t.Error("expected fail-closed when the mounter produced no SBOM")
	}
	if release != nil {
		t.Error("no usable release should be returned on failure")
	}
	if !released {
		t.Error("the partial mount must be torn down even though it had no SBOM")
	}
}
