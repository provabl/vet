// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssmAPI / s3API are the client subsets the remote scanner needs (mockable).
type ssmAPI interface {
	SendCommand(ctx context.Context, in *ssm.SendCommandInput, optFns ...func(*ssm.Options)) (*ssm.SendCommandOutput, error)
	GetCommandInvocation(ctx context.Context, in *ssm.GetCommandInvocationInput, optFns ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error)
}

type s3Getter interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// ssmScanner mounts the attached device on the helper instance read-only, runs
// syft over its root filesystem, uploads the SBOM to S3 (because a full-AMI SBOM
// exceeds SSM's ~24 KB inline output cap), and downloads it locally. It assumes
// the helper has syft and the AWS CLI on PATH and an instance profile that can
// PutObject to the staging bucket — documented as the operator's responsibility
// (the same managed/equipped helper slice 4's Config requires).
type ssmScanner struct {
	ssm      ssmAPI
	s3       s3Getter
	bucket   string        // S3 staging bucket for the SBOM hand-off
	localDir string        // where the downloaded SBOM is written
	poll     time.Duration // command-completion poll interval
	pollMax  int           // max polls before giving up
}

// NewSSMScanner builds a RemoteScanner. bucket is an S3 bucket both the helper
// (PutObject) and this process (GetObject) can reach; localDir is where the SBOM
// lands (e.g. the .vet store dir).
func NewSSMScanner(ctx context.Context, region, bucket, localDir string) (RemoteScanner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &ssmScanner{
		ssm:      ssm.NewFromConfig(cfg),
		s3:       s3.NewFromConfig(cfg),
		bucket:   bucket,
		localDir: localDir,
		poll:     5 * time.Second,
		pollMax:  60, // ~5 min
	}, nil
}

// remoteScript mounts the device read-only, syfts it, and uploads the SBOM to S3.
// It is deliberately defensive: mount read-only (-o ro) so the scan can never
// mutate the evidence, and always attempt an unmount. {{DEVICE}}/{{KEY}} are
// substituted; the bucket is passed via the script for a single self-contained
// command document.
const remoteScript = `set -euo pipefail
DEV="%s"
BUCKET="%s"
KEY="%s"
MNT="$(mktemp -d)"
cleanup() { umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
# The attached snapshot's root partition: try the whole device, then partition 1.
mount -o ro "$DEV" "$MNT" 2>/dev/null || mount -o ro "${DEV}1" "$MNT" 2>/dev/null || mount -o ro "${DEV}p1" "$MNT"
syft scan "dir:$MNT" -o cyclonedx-json --file /tmp/ami-sbom.json --quiet
aws s3 cp /tmp/ami-sbom.json "s3://$BUCKET/$KEY" --only-show-errors
`

// Scan runs the remote mount+syft, then downloads the produced SBOM. The S3 key
// is derived from the instance + a fixed suffix; the caller's localDir holds the
// result. Returns the local SBOM path.
func (s *ssmScanner) Scan(ctx context.Context, instanceID, device string) (string, error) {
	if s.bucket == "" {
		return "", fmt.Errorf("ssm scanner requires an S3 staging bucket")
	}
	key := fmt.Sprintf("vet-ami-scan/%s.cyclonedx.json", instanceID)
	script := fmt.Sprintf(remoteScript, device, s.bucket, key)

	out, err := s.ssm.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": {script}},
	})
	if err != nil {
		return "", fmt.Errorf("ssm send-command: %w", err)
	}
	cmdID := aws.ToString(out.Command.CommandId)

	if err := s.waitForCommand(ctx, cmdID, instanceID); err != nil {
		return "", err
	}

	localPath := s.localDir + "/ami-scan.cyclonedx.json"
	if err := s.download(ctx, key, localPath); err != nil {
		return "", fmt.Errorf("download SBOM from s3://%s/%s: %w", s.bucket, key, err)
	}
	return localPath, nil
}

// waitForCommand polls until the SSM command reaches a terminal state, returning
// an error (with the captured stderr) on anything but Success.
func (s *ssmScanner) waitForCommand(ctx context.Context, cmdID, instanceID string) error {
	for i := 0; i < s.pollMax; i++ {
		inv, err := s.ssm.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(cmdID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			// The invocation can briefly 404 right after SendCommand; tolerate it.
			if strings.Contains(err.Error(), "InvocationDoesNotExist") {
				if !sleep(ctx, s.poll) {
					return ctx.Err()
				}
				continue
			}
			return fmt.Errorf("ssm get-command-invocation: %w", err)
		}
		switch inv.Status {
		case ssmtypes.CommandInvocationStatusSuccess:
			return nil
		case ssmtypes.CommandInvocationStatusCancelled,
			ssmtypes.CommandInvocationStatusTimedOut,
			ssmtypes.CommandInvocationStatusFailed:
			return fmt.Errorf("remote scan %s on %s: %s\n%s",
				cmdID, instanceID, inv.Status, sanitizeOut(aws.ToString(inv.StandardErrorContent)))
		}
		if !sleep(ctx, s.poll) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("remote scan %s did not complete within the poll window", cmdID)
}

// download fetches the S3 object to localPath.
func (s *ssmScanner) download(ctx context.Context, key, localPath string) error {
	obj, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer func() { _ = obj.Body.Close() }()
	f, err := os.Create(localPath) // #nosec G304 — store-derived path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, obj.Body)
	return err
}

// sleep waits d or until ctx is done; returns false if the context ended.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// sanitizeOut strips control characters and bounds remote stderr before it goes
// into an error message.
func sanitizeOut(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	const max = 2000
	if len(out) > max {
		return out[:max] + "…(truncated)"
	}
	return out
}
