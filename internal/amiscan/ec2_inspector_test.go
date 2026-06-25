// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeDescribe struct {
	out *ec2.DescribeImagesOutput
	err error
}

func (f fakeDescribe) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return f.out, f.err
}

func img(root string, mappings ...ec2types.BlockDeviceMapping) *ec2.DescribeImagesOutput {
	return &ec2.DescribeImagesOutput{Images: []ec2types.Image{{
		RootDeviceName:      aws.String(root),
		BlockDeviceMappings: mappings,
	}}}
}

func ebs(dev, snap string) ec2types.BlockDeviceMapping {
	return ec2types.BlockDeviceMapping{
		DeviceName: aws.String(dev),
		Ebs:        &ec2types.EbsBlockDevice{SnapshotId: aws.String(snap)},
	}
}

func TestBackingSnapshot_PrefersRootDevice(t *testing.T) {
	i := &ec2Inspector{client: fakeDescribe{out: img("/dev/xvda",
		ebs("/dev/sdb", "snap-data"),
		ebs("/dev/xvda", "snap-root"),
	)}}
	got, err := i.BackingSnapshot(context.Background(), "ami-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "snap-root" {
		t.Errorf("got %q, want snap-root (the root device's snapshot)", got)
	}
}

func TestBackingSnapshot_FallsBackToFirstEBS(t *testing.T) {
	// Root device name doesn't match any mapping → fall back to the first EBS.
	i := &ec2Inspector{client: fakeDescribe{out: img("/dev/xvda",
		ebs("/dev/sdb", "snap-only"),
	)}}
	got, _ := i.BackingSnapshot(context.Background(), "ami-1")
	if got != "snap-only" {
		t.Errorf("got %q, want snap-only", got)
	}
}

func TestBackingSnapshot_NotFound(t *testing.T) {
	i := &ec2Inspector{client: fakeDescribe{out: &ec2.DescribeImagesOutput{}}}
	if _, err := i.BackingSnapshot(context.Background(), "ami-missing"); err == nil {
		t.Error("expected an error when the AMI is not found")
	}
}

func TestBackingSnapshot_APIError(t *testing.T) {
	i := &ec2Inspector{client: fakeDescribe{err: errors.New("AccessDenied")}}
	if _, err := i.BackingSnapshot(context.Background(), "ami-1"); err == nil {
		t.Error("expected the DescribeImages error to propagate")
	}
}

func TestBackingSnapshot_NoEBSMapping(t *testing.T) {
	// An instance-store AMI with no EBS mapping → empty (caller fails closed).
	i := &ec2Inspector{client: fakeDescribe{out: img("/dev/sda1")}}
	got, _ := i.BackingSnapshot(context.Background(), "ami-1")
	if got != "" {
		t.Errorf("got %q, want empty (no EBS snapshot to scan)", got)
	}
}
