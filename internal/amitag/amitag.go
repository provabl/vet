// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package amitag writes the attest:vetted tag to an AWS AMI when vet's gate
// passes. The tag is what ground's AMI-launch-gating SCP keys on
// (ec2:ResourceTag/attest:vetted == "true" to allow ec2:RunInstances), and a
// companion lockdown SCP restricts who may set it to a designated vetter
// principal — so vet's CI (running this) must be that principal. This is the
// producer half of provabl#13's launch-gating loop, mirroring how the nitro tool
// writes the attest:nitro-attested IAM tag.
package amitag

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// TagVetted is the AMI tag key ground's launch-gating SCP requires. Defined once
// here so the key never drifts from ground's policy (mirrors how the nitro tool
// pins attest:nitro-attested).
const TagVetted = "attest:vetted"

// TagPCRPrefix is the prefix for golden boot-measurement tags written to a vetted
// AMI by `vet ami-reference` (e.g. attest:pcr0, attest:pcr7). At launch, a running
// instance's attestation PCR is checked against the AMI's golden value to bind the
// instance to the vetted image (provabl#13). Like attest:vetted, these keys are
// locked to the vetter principal by ground's lockdown SCP (a forgeable golden PCR
// would defeat the binding).
const TagPCRPrefix = "attest:pcr"

// Tagger writes tags to an AMI. Implemented by the AWS EC2 client in production;
// mocked in tests. The id is an AMI id (ami-...).
type Tagger interface {
	TagImage(ctx context.Context, amiID string, tags map[string]string) error
}

// awsTagger adapts the AWS EC2 client to Tagger.
type awsTagger struct{ client *ec2.Client }

// New builds an EC2-backed Tagger for the given region.
func New(ctx context.Context, region string) (Tagger, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &awsTagger{client: ec2.NewFromConfig(cfg)}, nil
}

// TagImage sets tags on the AMI via ec2:CreateTags (the call ground's lockdown SCP
// restricts to the vetter principal).
func (t *awsTagger) TagImage(ctx context.Context, amiID string, tags map[string]string) error {
	in := &ec2.CreateTagsInput{Resources: []string{amiID}}
	for k, v := range tags {
		in.Tags = append(in.Tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err := t.client.CreateTags(ctx, in)
	return err
}
