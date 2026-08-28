package aws

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// assertSemanticTrustDoc asserts the document equals the expected trust
// policy by unmarshal-and-compare, not byte equality.
func assertSemanticTrustDoc(t *testing.T, doc string) {
	t.Helper()
	want := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/issuer.test.example"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"issuer.test.example:aud":"sts.amazonaws.com","issuer.test.example:sub":"fai:t/i"}}}]}`
	var gotV, wantV any
	if err := json.Unmarshal([]byte(doc), &gotV); err != nil {
		t.Fatalf("trust policy does not parse: %v\n%s", err, doc)
	}
	if err := json.Unmarshal([]byte(want), &wantV); err != nil {
		t.Fatalf("bad expectation: %v", err)
	}
	if !reflect.DeepEqual(gotV, wantV) {
		t.Fatalf("trust policy = %s\nwant semantic equal to %s", doc, want)
	}
}

func tag(k, v string) types.Tag {
	return types.Tag{Key: awssdk.String(k), Value: awssdk.String(v)}
}

func TestEnsureRoleCreates(t *testing.T) {
	roleArn := "arn:aws:iam::111122223333:role/fai-t-i"
	f := &fakeIAM{t: t, createRole: func(in *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
		if awssdk.ToString(in.RoleName) != "fai-t-i" {
			t.Fatalf("RoleName = %q", awssdk.ToString(in.RoleName))
		}
		if awssdk.ToString(in.Description) != "formae.ai oidc connection" {
			t.Fatalf("Description = %q", awssdk.ToString(in.Description))
		}
		if awssdk.ToInt32(in.MaxSessionDuration) != 3600 {
			t.Fatalf("MaxSessionDuration = %d", awssdk.ToInt32(in.MaxSessionDuration))
		}
		got := map[string]string{}
		for _, tg := range in.Tags {
			got[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
		}
		if got["formae-ai:owner"] != "provx" || got["formae-ai:subject"] != "fai:t/i" {
			t.Fatalf("Tags = %v", got)
		}
		assertSemanticTrustDoc(t, awssdk.ToString(in.AssumeRolePolicyDocument))
		return &iam.CreateRoleOutput{Role: &types.Role{Arn: awssdk.String(roleArn)}}, nil
	}}
	arn, out, err := newTestAWS(t, f).ensureRole(context.Background())
	if err != nil || out != RoleCreated || arn != roleArn {
		t.Fatalf("arn=%q out=%v err=%v", arn, out, err)
	}
}

func TestEnsureRoleConvergesOwned(t *testing.T) {
	getRoleArn := "arn:aws:iam::111122223333:role/custom-path/fai-t-i"
	updated := false
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{
				tag("formae-ai:owner", "provx"),
				tag("formae-ai:subject", "fai:t/i"),
			}}, nil
		},
		updateAssumeRolePolicy: func(in *iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
			assertSemanticTrustDoc(t, awssdk.ToString(in.PolicyDocument))
			updated = true
			return &iam.UpdateAssumeRolePolicyOutput{}, nil
		},
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{Arn: awssdk.String(getRoleArn)}}, nil
		},
	}
	arn, out, err := newTestAWS(t, f).ensureRole(context.Background())
	if err != nil || out != RoleConverged || arn != getRoleArn {
		t.Fatalf("arn=%q out=%v err=%v", arn, out, err)
	}
	if !updated {
		t.Fatal("UpdateAssumeRolePolicy was not called")
	}
}

func TestEnsureRoleTagsPaginated(t *testing.T) {
	page := 0
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(in *iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			page++
			switch page {
			case 1:
				return &iam.ListRoleTagsOutput{
					IsTruncated: true,
					Marker:      awssdk.String("m"),
					Tags:        []types.Tag{tag("formae-ai:subject", "fai:t/i")},
				}, nil
			case 2:
				if awssdk.ToString(in.Marker) != "m" {
					t.Fatalf("page 2 Marker = %q", awssdk.ToString(in.Marker))
				}
				return &iam.ListRoleTagsOutput{Tags: []types.Tag{tag("formae-ai:owner", "provx")}}, nil
			default:
				t.Fatalf("unexpected page %d", page)
				return nil, nil
			}
		},
		updateAssumeRolePolicy: func(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
			return &iam.UpdateAssumeRolePolicyOutput{}, nil
		},
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{Arn: awssdk.String("arn:aws:iam::111122223333:role/fai-t-i")}}, nil
		},
	}
	_, out, err := newTestAWS(t, f).ensureRole(context.Background())
	if err != nil || out != RoleConverged {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestEnsureRoleCollisionForeignOwner(t *testing.T) {
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{tag("formae-ai:owner", "cloudformation")}}, nil
		},
		// updateAssumeRolePolicy nil: any mutation call fails the test.
	}
	_, _, err := newTestAWS(t, f).ensureRole(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if collision.Owner != "cloudformation" {
		t.Fatalf("Owner = %q", collision.Owner)
	}
}

func TestEnsureRoleCollisionNoTags(t *testing.T) {
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{}, nil
		},
	}
	_, _, err := newTestAWS(t, f).ensureRole(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if collision.Owner != "" {
		t.Fatalf("Owner = %q, want empty", collision.Owner)
	}
}

func TestEnsureRoleCollisionSubjectMismatch(t *testing.T) {
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) {
			return &iam.ListRoleTagsOutput{Tags: []types.Tag{
				tag("formae-ai:owner", "provx"),
				tag("formae-ai:subject", "fai:other/x"),
			}}, nil
		},
	}
	_, _, err := newTestAWS(t, f).ensureRole(context.Background())
	var collision *RoleCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("want RoleCollisionError, got %v", err)
	}
	if !strings.Contains(err.Error(), "fai:t/i") || !strings.Contains(err.Error(), "fai:other/x") {
		t.Fatalf("message must name both subjects: %v", err)
	}
}

func TestEnsureRoleCreateErrorWrapped(t *testing.T) {
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.LimitExceededException{}
		},
	}
	_, _, err := newTestAWS(t, f).ensureRole(context.Background())
	var limit *types.LimitExceededException
	if !errors.As(err, &limit) {
		t.Fatalf("SDK error must stay discoverable through the wrap, got %v", err)
	}
}
