package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestCreateHappyPath(t *testing.T) {
	const roleArn = "arn:aws:iam::111122223333:role/fai-t-i"
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return &iam.CreateOpenIDConnectProviderOutput{}, nil
		},
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return &iam.CreateRoleOutput{Role: &types.Role{Arn: awssdk.String(roleArn)}}, nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{}, nil
		},
		attachRolePolicy: func(*iam.AttachRolePolicyInput) (*iam.AttachRolePolicyOutput, error) {
			return &iam.AttachRolePolicyOutput{}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
	}
	res, err := newTestAWS(t, f).Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != ProviderCreated || res.Role != RoleCreated || res.RoleArn != roleArn {
		t.Fatalf("res = %+v", res)
	}
	if res.DetachedPolicies != nil || res.DeletedInline != nil {
		t.Fatalf("fresh account must remove nothing: %+v", res)
	}
}

func TestCreateRerunConverges(t *testing.T) {
	const roleArn = "arn:aws:iam::111122223333:role/fai-t-i"
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return &iam.GetOpenIDConnectProviderOutput{
				Url:          awssdk.String("issuer.test.example"),
				ClientIDList: []string{"sts.amazonaws.com"},
			}, nil
		},
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{
				tag("formae-ai:owner", "provx"),
				tag("formae-ai:subject", "fai:t/i"),
			}}, nil
		},
		updateAssumeRolePolicy: func(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
			return &iam.UpdateAssumeRolePolicyOutput{}, nil
		},
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{Arn: awssdk.String(roleArn)}}, nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{attachedPolicy(ManagedPolicyArn)}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{InlinePolicyName}}, nil
		},
		putRolePolicy: func(*iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
			return &iam.PutRolePolicyOutput{}, nil
		},
	}
	res, err := newTestAWS(t, f).Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != ProviderExisted || res.Role != RoleConverged || res.RoleArn != roleArn {
		t.Fatalf("res = %+v", res)
	}
}

func TestCreateStopsOnRoleCollision(t *testing.T) {
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return &iam.CreateOpenIDConnectProviderOutput{}, nil
		},
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{tag("formae-ai:owner", "cloudformation")}}, nil
		},
		// All posture fields nil: any posture call fails the test.
	}
	_, err := newTestAWS(t, f).Create(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
}

func TestCreateStopsOnProviderConflict(t *testing.T) {
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return &iam.GetOpenIDConnectProviderOutput{Url: awssdk.String("evil.example.com")}, nil
		},
		// All role fields nil: any role call fails the test.
	}
	_, err := newTestAWS(t, f).Create(context.Background())
	var conflict *ProviderConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want ProviderConflictError, got %v", err)
	}
}
