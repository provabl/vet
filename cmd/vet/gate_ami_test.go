// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/provabl/vet/internal/amitag"
)

// fakeTagger records TagImage calls so tests can assert what (if anything) was
// written, with no AWS.
type fakeTagger struct {
	calls []taggedCall
	err   error
}

type taggedCall struct {
	amiID string
	tags  map[string]string
}

func (f *fakeTagger) TagImage(_ context.Context, amiID string, tags map[string]string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, taggedCall{amiID: amiID, tags: tags})
	return nil
}

func TestTagIfVetted_PassWritesVettedTag(t *testing.T) {
	f := &fakeTagger{}
	tagged, err := tagIfVetted(context.Background(), f, "ami-0abc123", true)
	if err != nil {
		t.Fatalf("tagIfVetted: %v", err)
	}
	if !tagged {
		t.Fatal("expected a tag to be written on a passing gate")
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 TagImage call, got %d", len(f.calls))
	}
	c := f.calls[0]
	if c.amiID != "ami-0abc123" {
		t.Errorf("tagged %q, want ami-0abc123", c.amiID)
	}
	if c.tags[amitag.TagVetted] != "true" {
		t.Errorf("tags[%s] = %q, want true", amitag.TagVetted, c.tags[amitag.TagVetted])
	}
}

// The fail-closed guarantee: a failing gate must write NO tag — so ground's SCP
// keeps denying RunInstances of an AMI that didn't pass.
func TestTagIfVetted_FailWritesNothing(t *testing.T) {
	f := &fakeTagger{}
	tagged, err := tagIfVetted(context.Background(), f, "ami-0abc123", false)
	if err != nil {
		t.Fatalf("tagIfVetted: %v", err)
	}
	if tagged {
		t.Fatal("expected NO tag on a failing gate (fail-closed)")
	}
	if len(f.calls) != 0 {
		t.Fatalf("expected 0 TagImage calls on a failing gate, got %d", len(f.calls))
	}
}

// No tagger configured (gate without --tag-vetted) must never tag, even on a pass.
func TestTagIfVetted_NilTaggerNeverTags(t *testing.T) {
	tagged, err := tagIfVetted(context.Background(), nil, "ami-0abc123", true)
	if err != nil || tagged {
		t.Fatalf("nil tagger must not tag: tagged=%v err=%v", tagged, err)
	}
}

// A tagger error on a passing gate must propagate (don't silently report success).
func TestTagIfVetted_TaggerErrorPropagates(t *testing.T) {
	f := &fakeTagger{err: errors.New("AccessDenied")}
	if _, err := tagIfVetted(context.Background(), f, "ami-0abc123", true); err == nil {
		t.Fatal("expected the tagger error to propagate")
	}
}

func TestIsAMIRef(t *testing.T) {
	cases := map[string]bool{
		"ami-0abc123def":      true,
		"ghcr.io/org/img:v1":  false,
		"./binary":            false,
		"github.com/org/repo": false,
	}
	for ref, want := range cases {
		if got := isAMIRef(ref); got != want {
			t.Errorf("isAMIRef(%q) = %v, want %v", ref, got, want)
		}
	}
}
