// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package amiscan

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ec2VolumeAPI is the subset of the EC2 client the VolumeManager needs (mockable).
type ec2VolumeAPI interface {
	CreateVolume(ctx context.Context, in *ec2.CreateVolumeInput, optFns ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	AttachVolume(ctx context.Context, in *ec2.AttachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(ctx context.Context, in *ec2.DetachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
	DeleteVolume(ctx context.Context, in *ec2.DeleteVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	ec2.DescribeVolumesAPIClient
}

// ec2Volumes is the live VolumeManager: thin wrappers over the EC2 volume calls,
// each waiting for the resource to reach the state the next step needs. The
// lifecycle orchestration + guaranteed teardown lives in the Mounter (slice 4,
// fake-tested); this adapter only makes the calls.
type ec2Volumes struct {
	client ec2VolumeAPI
	// waitTimeout bounds each state transition wait.
	waitTimeout time.Duration
}

// NewEC2VolumeManager builds a VolumeManager backed by the AWS EC2 client. The
// scan volumes it creates are tagged ephemeral so a stray one is easy to find.
func NewEC2VolumeManager(ctx context.Context, region string) (VolumeManager, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &ec2Volumes{client: ec2.NewFromConfig(cfg), waitTimeout: 3 * time.Minute}, nil
}

// CreateFromSnapshot creates a volume from the snapshot in az and waits until it
// is available. The volume is tagged so it is identifiable as a vet scan artifact.
func (v *ec2Volumes) CreateFromSnapshot(ctx context.Context, snapshotID, az string) (string, error) {
	out, err := v.client.CreateVolume(ctx, &ec2.CreateVolumeInput{
		SnapshotId:       aws.String(snapshotID),
		AvailabilityZone: aws.String(az),
		VolumeType:       ec2types.VolumeTypeGp3,
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeVolume,
			Tags: []ec2types.Tag{
				{Key: aws.String("Name"), Value: aws.String("vet-ami-scan")},
				{Key: aws.String("vet:ephemeral"), Value: aws.String("true")},
				{Key: aws.String("vet:purpose"), Value: aws.String("ami-content-scan")},
			},
		}},
	})
	if err != nil {
		return "", err
	}
	volID := aws.ToString(out.VolumeId)
	w := ec2.NewVolumeAvailableWaiter(v.client)
	if err := w.Wait(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volID}}, v.waitTimeout); err != nil {
		return volID, fmt.Errorf("waiting for volume %s to become available: %w", volID, err)
	}
	return volID, nil
}

// Attach attaches the volume to the instance at device and waits until in-use.
func (v *ec2Volumes) Attach(ctx context.Context, volumeID, instanceID, device string) error {
	_, err := v.client.AttachVolume(ctx, &ec2.AttachVolumeInput{
		VolumeId:   aws.String(volumeID),
		InstanceId: aws.String(instanceID),
		Device:     aws.String(device),
	})
	if err != nil {
		return err
	}
	w := ec2.NewVolumeInUseWaiter(v.client)
	if err := w.Wait(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volumeID}}, v.waitTimeout); err != nil {
		return fmt.Errorf("waiting for volume %s to attach: %w", volumeID, err)
	}
	return nil
}

// Detach detaches the volume and waits until it is available again (a volume
// cannot be deleted while still attaching/detaching).
func (v *ec2Volumes) Detach(ctx context.Context, volumeID string) error {
	_, err := v.client.DetachVolume(ctx, &ec2.DetachVolumeInput{VolumeId: aws.String(volumeID)})
	if err != nil {
		return err
	}
	w := ec2.NewVolumeAvailableWaiter(v.client)
	if err := w.Wait(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volumeID}}, v.waitTimeout); err != nil {
		return fmt.Errorf("waiting for volume %s to detach: %w", volumeID, err)
	}
	return nil
}

// Delete deletes the volume.
func (v *ec2Volumes) Delete(ctx context.Context, volumeID string) error {
	_, err := v.client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: aws.String(volumeID)})
	return err
}
