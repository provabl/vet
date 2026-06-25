// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// describeImagesAPI is the read-only EC2 call the inspector needs (mockable).
type describeImagesAPI interface {
	DescribeImages(ctx context.Context, in *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// ec2Inspector resolves an AMI's backing snapshot via ec2:DescribeImages.
type ec2Inspector struct{ client describeImagesAPI }

// NewEC2Inspector builds an ImageInspector backed by the AWS EC2 client.
func NewEC2Inspector(ctx context.Context, region string) (ImageInspector, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &ec2Inspector{client: ec2.NewFromConfig(cfg)}, nil
}

// BackingSnapshot returns the EBS snapshot backing the AMI's root device. It picks
// the mapping matching the image's RootDeviceName, falling back to the first
// EBS mapping — an AMI's root volume is the one whose filesystem we scan.
func (i *ec2Inspector) BackingSnapshot(ctx context.Context, amiID string) (string, error) {
	out, err := i.client.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{amiID}})
	if err != nil {
		return "", err
	}
	if len(out.Images) == 0 {
		return "", fmt.Errorf("AMI %s not found", amiID)
	}
	img := out.Images[0]
	root := aws.ToString(img.RootDeviceName)
	var firstEBS string
	for _, m := range img.BlockDeviceMappings {
		if m.Ebs == nil || m.Ebs.SnapshotId == nil {
			continue
		}
		snap := aws.ToString(m.Ebs.SnapshotId)
		if firstEBS == "" {
			firstEBS = snap
		}
		if aws.ToString(m.DeviceName) == root {
			return snap, nil
		}
	}
	return firstEBS, nil
}
