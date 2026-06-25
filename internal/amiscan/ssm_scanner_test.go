// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeSSM scripts a SendCommand id and a sequence of GetCommandInvocation results.
type fakeSSM struct {
	sentScript string
	statuses   []ssmtypes.CommandInvocationStatus // consumed one per poll
	stderr     string
	idx        int
}

func (f *fakeSSM) SendCommand(_ context.Context, in *ssm.SendCommandInput, _ ...func(*ssm.Options)) (*ssm.SendCommandOutput, error) {
	if cmds := in.Parameters["commands"]; len(cmds) > 0 {
		f.sentScript = cmds[0]
	}
	return &ssm.SendCommandOutput{Command: &ssmtypes.Command{CommandId: aws.String("cmd-1")}}, nil
}

func (f *fakeSSM) GetCommandInvocation(_ context.Context, _ *ssm.GetCommandInvocationInput, _ ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error) {
	st := f.statuses[f.idx]
	if f.idx < len(f.statuses)-1 {
		f.idx++
	}
	return &ssm.GetCommandInvocationOutput{Status: st, StandardErrorContent: aws.String(f.stderr)}, nil
}

// fakeS3 returns canned object bytes.
type fakeS3 struct {
	body   string
	gotKey string
	getErr error
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gotKey = aws.ToString(in.Key)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func newScanner(t *testing.T, ss ssmAPI, s3c s3Getter) *ssmScanner {
	t.Helper()
	return &ssmScanner{
		ssm: ss, s3: s3c,
		bucket: "stage-bucket", localDir: t.TempDir(),
		poll: time.Millisecond, pollMax: 10,
	}
}

func TestScanner_SuccessDownloadsSBOM(t *testing.T) {
	ss := &fakeSSM{statuses: []ssmtypes.CommandInvocationStatus{
		ssmtypes.CommandInvocationStatusInProgress,
		ssmtypes.CommandInvocationStatusSuccess,
	}}
	s3c := &fakeS3{body: `{"bomFormat":"CycloneDX"}`}
	sc := newScanner(t, ss, s3c)

	path, err := sc.Scan(context.Background(), "i-helper", "/dev/sdf")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// The remote script must mount read-only and target the attached device.
	if !strings.Contains(ss.sentScript, "mount -o ro") || !strings.Contains(ss.sentScript, "/dev/sdf") {
		t.Errorf("script missing read-only mount of the device:\n%s", ss.sentScript)
	}
	if !strings.Contains(ss.sentScript, "syft scan") {
		t.Errorf("script does not run syft:\n%s", ss.sentScript)
	}
	// S3 key is instance-scoped; the SBOM is downloaded locally.
	if !strings.Contains(s3c.gotKey, "i-helper") {
		t.Errorf("S3 key = %q, want it to include the instance id", s3c.gotKey)
	}
	if b, _ := readFile(path); !strings.Contains(b, "CycloneDX") {
		t.Errorf("downloaded SBOM not written to %s", path)
	}
}

func TestScanner_RemoteFailureSurfacesStderr(t *testing.T) {
	ss := &fakeSSM{
		statuses: []ssmtypes.CommandInvocationStatus{ssmtypes.CommandInvocationStatusFailed},
		stderr:   "mount: wrong fs type",
	}
	sc := newScanner(t, ss, &fakeS3{})
	_, err := sc.Scan(context.Background(), "i-helper", "/dev/sdf")
	if err == nil || !strings.Contains(err.Error(), "wrong fs type") {
		t.Fatalf("expected remote stderr in the error, got %v", err)
	}
}

func TestScanner_RequiresBucket(t *testing.T) {
	sc := &ssmScanner{ssm: &fakeSSM{}, s3: &fakeS3{}, poll: time.Millisecond, pollMax: 1}
	if _, err := sc.Scan(context.Background(), "i-helper", "/dev/sdf"); err == nil {
		t.Error("expected an error when no staging bucket is configured")
	}
}

func TestScanner_TimesOut(t *testing.T) {
	ss := &fakeSSM{statuses: []ssmtypes.CommandInvocationStatus{ssmtypes.CommandInvocationStatusInProgress}}
	sc := newScanner(t, ss, &fakeS3{})
	sc.pollMax = 3
	_, err := sc.Scan(context.Background(), "i-helper", "/dev/sdf")
	if err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("expected a poll-window timeout, got %v", err)
	}
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p) //nolint:gosec // test path
	return string(b), err
}
