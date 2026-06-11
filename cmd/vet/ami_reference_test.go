// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestPCRTagsFromFlags_Valid(t *testing.T) {
	tags, err := pcrTagsFromFlags([]string{"0=ab12", "7=cd34"})
	if err != nil {
		t.Fatalf("pcrTagsFromFlags: %v", err)
	}
	if tags["attest:pcr0"] != "ab12" {
		t.Errorf("attest:pcr0 = %q, want ab12", tags["attest:pcr0"])
	}
	if tags["attest:pcr7"] != "cd34" {
		t.Errorf("attest:pcr7 = %q, want cd34", tags["attest:pcr7"])
	}
	if len(tags) != 2 {
		t.Errorf("got %d tags, want 2", len(tags))
	}
}

func TestPCRTagsFromFlags_Rejects(t *testing.T) {
	cases := map[string][]string{
		"no equals":        {"0ab12"},
		"non-numeric idx":  {"x=ab"},
		"idx out of range": {"24=ab"},
		"negative idx":     {"-1=ab"},
		"empty value":      {"0="},
		"non-hex value":    {"0=zz"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := pcrTagsFromFlags(in); err == nil {
				t.Errorf("pcrTagsFromFlags(%v) = nil error, want rejection", in)
			}
		})
	}
}
