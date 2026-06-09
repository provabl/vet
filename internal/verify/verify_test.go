// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactHash_DigestPinnedRef(t *testing.T) {
	ref := "ghcr.io/org/app@sha256:abc123def456"
	if got := artifactHash(ref); got != "sha256:abc123def456" {
		t.Errorf("artifactHash(%q) = %q, want sha256:abc123def456", ref, got)
	}
}

func TestArtifactHash_BareTagIsEmpty(t *testing.T) {
	// A tag without a digest cannot be hashed without pulling — empty is honest.
	if got := artifactHash("ghcr.io/org/app:v1.0"); got != "" {
		t.Errorf("artifactHash(bare tag) = %q, want empty", got)
	}
}

func TestArtifactHash_LocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	content := []byte("hello provabl")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	if got := artifactHash(path); got != want {
		t.Errorf("artifactHash(local file) = %q, want %q", got, want)
	}
}

func TestArtifactHash_MissingLocalFileIsEmpty(t *testing.T) {
	if got := artifactHash("/nonexistent/path/artifact.bin"); got != "" {
		t.Errorf("artifactHash(missing file) = %q, want empty", got)
	}
}
