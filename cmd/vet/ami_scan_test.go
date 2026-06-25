// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestAMIScanCmd_Validation covers the argument/flag guards that run before any
// AWS call — a non-AMI ref and missing required flags must error clearly.
func TestAMIScanCmd_Validation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"non-AMI ref", []string{"ghcr.io/o/i:v1", "--helper-instance", "i-1", "--az", "us-east-1a", "--scan-bucket", "b"}},
		{"missing helper", []string{"ami-0abc", "--az", "us-east-1a", "--scan-bucket", "b"}},
		{"missing az", []string{"ami-0abc", "--helper-instance", "i-1", "--scan-bucket", "b"}},
		{"missing bucket", []string{"ami-0abc", "--helper-instance", "i-1", "--az", "us-east-1a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := amiScanCmd()
			cmd.SetArgs(tc.args)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			if err := cmd.Execute(); err == nil {
				t.Errorf("expected an error for %q", tc.name)
			}
		})
	}
}

// TestAMIScanCmd_Help confirms the prerequisites are documented on the command —
// the operator needs to know the helper instance + bucket are their responsibility.
func TestAMIScanCmd_Help(t *testing.T) {
	long := amiScanCmd().Long
	for _, want := range []string{"helper instance", "snapshot", "grype", "S3 bucket"} {
		if !strings.Contains(long, want) {
			t.Errorf("ami-scan help missing %q", want)
		}
	}
}
