// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type mockSTS struct {
	arn string
	err error
}

func (m mockSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String(m.arn)}, nil
}

type mockIAMSim struct {
	denied map[string]bool
	err    error
}

func (m mockIAMSim) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	var results []iamtypes.EvaluationResult
	for _, a := range in.ActionNames {
		dec := iamtypes.PolicyEvaluationDecisionTypeAllowed
		if m.denied[a] {
			dec = iamtypes.PolicyEvaluationDecisionTypeExplicitDeny
		}
		results = append(results, iamtypes.EvaluationResult{EvalActionName: aws.String(a), EvalDecision: dec})
	}
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: results}, nil
}

const testARN = "arn:aws:iam::942542972736:role/vet-runner"

func allOK(rs []Result) bool {
	for _, r := range rs {
		if !r.Status {
			return false
		}
	}
	return true
}

func TestCheck_AllAllowed(t *testing.T) {
	rs := check(context.Background(), mockSTS{arn: testARN}, mockIAMSim{})
	if len(rs) != len(vetRequiredActions) {
		t.Fatalf("expected %d results, got %d", len(vetRequiredActions), len(rs))
	}
	if !allOK(rs) {
		t.Error("expected all actions allowed → all ok")
	}
}

// A denied action surfaces as a non-ok result with remediation (fail-closed).
func TestCheck_DeniedActionIsError(t *testing.T) {
	target := vetRequiredActions[len(vetRequiredActions)-1] // the tool-specific action
	rs := check(context.Background(), mockSTS{arn: testARN}, mockIAMSim{denied: map[string]bool{target: true}})
	var found bool
	for _, r := range rs {
		if r.Name == target {
			found = true
			if r.Status || r.Severity != "error" || r.Remediation == "" {
				t.Errorf("denied action = %+v; want non-ok error with remediation", r)
			}
		}
	}
	if !found {
		t.Fatalf("no result for the denied action %q", target)
	}
	if allOK(rs) {
		t.Error("a denied action must make the set not-all-ok")
	}
}

func TestCheck_CallerIdentityErrorFailsClosed(t *testing.T) {
	rs := check(context.Background(), mockSTS{err: errors.New("ExpiredToken")}, mockIAMSim{})
	if len(rs) != 1 || rs[0].Status {
		t.Fatalf("expected one error result on GetCallerIdentity failure, got %+v", rs)
	}
}

func TestCheck_SimulatorErrorFailsClosed(t *testing.T) {
	rs := check(context.Background(), mockSTS{arn: testARN}, mockIAMSim{err: errors.New("AccessDenied")})
	if len(rs) != 1 || rs[0].Status {
		t.Fatalf("expected one fail-closed error result on simulator failure, got %+v", rs)
	}
	if rs[0].Remediation == "" {
		t.Error("fail-closed result should explain how to enable the self-check")
	}
}
