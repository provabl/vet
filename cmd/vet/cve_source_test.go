// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestResolveCVESource(t *testing.T) {
	cases := []struct {
		name    string
		flag    string
		ref     string
		want    string // expected Source.Name()
		wantErr bool
	}{
		{"auto routes AMI to grype", "auto", "ami-0abc123", "grype", false},
		{"auto routes image to osv", "auto", "ghcr.io/org/img:v1", "osv", false},
		{"empty defaults like auto (AMI)", "", "ami-0abc123", "grype", false},
		{"explicit osv on an AMI", "osv", "ami-0abc123", "osv", false},
		{"explicit grype on an image", "grype", "ghcr.io/org/img:v1", "grype", false},
		{"unknown source errors", "trivy", "ami-0abc123", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := resolveCVESource(tc.flag, tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if src.Name() != tc.want {
				t.Errorf("source = %q, want %q", src.Name(), tc.want)
			}
		})
	}
}
