package aws

import (
	"context"
	"errors"
	"slices"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func tagValue(tags []types.Tag, key string) (string, bool) {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == key {
			return awssdk.ToString(t.Value), true
		}
	}
	return "", false
}

// ourRoleTags is what assertRoleOwnership requires before it will converge a
// role that already exists.
func ourRoleTags() *iam.ListRoleTagsOutput {
	return &iam.ListRoleTagsOutput{Tags: []types.Tag{
		tag(tagOwner, tagOwnerValue),
		tag(tagSubject, "fai:t/i"),
	}}
}

func TestEnsureRoleCreatesWithTheOwnershipTag(t *testing.T) {
	var got []types.Tag
	f := &fakeIAM{t: t, createRole: func(in *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
		got = in.Tags
		return &iam.CreateRoleOutput{Role: &types.Role{Arn: awssdk.String("arn:aws:iam::111122223333:role/fai-t-i")}}, nil
	}}

	if _, _, err := newTestAWS(t, f).ensureRole(context.Background()); err != nil {
		t.Fatal(err)
	}

	v, ok := tagValue(got, tagOwned)
	if !ok || v != tagOwnedValue {
		t.Fatalf("role must be created carrying %s=%s, tags = %+v", tagOwned, tagOwnedValue, got)
	}
	if _, ok := tagValue(got, tagOwner); !ok {
		t.Fatalf("the provenance tag must survive alongside it, tags = %+v", got)
	}
}

func TestEnsureRoleTagsARoleThatPredatesTheOwnershipTag(t *testing.T) {
	var tagged []types.Tag
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) { return ourRoleTags(), nil },
		updateAssumeRolePolicy: func(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
			return &iam.UpdateAssumeRolePolicyOutput{}, nil
		},
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{Arn: awssdk.String("arn:aws:iam::111122223333:role/fai-t-i")}}, nil
		},
		tagRole: func(in *iam.TagRoleInput) (*iam.TagRoleOutput, error) {
			tagged = in.Tags
			return &iam.TagRoleOutput{}, nil
		},
	}

	if _, _, err := newTestAWS(t, f).ensureRole(context.Background()); err != nil {
		t.Fatal(err)
	}

	if v, ok := tagValue(tagged, tagOwned); !ok || v != tagOwnedValue {
		t.Fatalf("converging an existing role must add %s=%s, tags = %+v", tagOwned, tagOwnedValue, tagged)
	}
}

func TestEnsureRoleSurvivesATaggingRefusal(t *testing.T) {
	f := &fakeIAM{t: t,
		createRole: func(*iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		listRoleTags: func(*iam.ListRoleTagsInput) (*iam.ListRoleTagsOutput, error) { return ourRoleTags(), nil },
		updateAssumeRolePolicy: func(*iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error) {
			return &iam.UpdateAssumeRolePolicyOutput{}, nil
		},
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &types.Role{Arn: awssdk.String("arn:aws:iam::111122223333:role/fai-t-i")}}, nil
		},
		tagRole: func(*iam.TagRoleInput) (*iam.TagRoleOutput, error) {
			return nil, errors.New("AccessDenied: not authorized to perform iam:TagRole")
		},
	}

	if _, outcome, err := newTestAWS(t, f).ensureRole(context.Background()); err != nil {
		t.Fatalf("a refused tag must not fail the connection: %v", err)
	} else if outcome != RoleConverged {
		t.Fatalf("outcome = %v", outcome)
	}
}

func TestEnsureProviderTagsThroughItsOwnCall(t *testing.T) {
	var createTags []types.Tag
	var tagged []types.Tag
	f := &fakeIAM{t: t,
		createOIDCProvider: func(in *iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			createTags = in.Tags
			return &iam.CreateOpenIDConnectProviderOutput{}, nil
		},
		tagOIDCProvider: func(in *iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error) {
			tagged = in.Tags
			return &iam.TagOpenIDConnectProviderOutput{}, nil
		},
	}

	if _, err := newTestAWS(t, f).ensureProvider(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Passing Tags to the create would newly require iam:TagOpenIDConnectProvider
	// on a call that has never needed it, so the tag rides its own request.
	if createTags != nil {
		t.Fatalf("the create must not carry tags, got %+v", createTags)
	}
	if v, ok := tagValue(tagged, tagOwned); !ok || v != tagOwnedValue {
		t.Fatalf("the provider must be tagged %s=%s, tags = %+v", tagOwned, tagOwnedValue, tagged)
	}
}

func TestEnsureProviderSurvivesATaggingRefusal(t *testing.T) {
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return &iam.CreateOpenIDConnectProviderOutput{}, nil
		},
		tagOIDCProvider: func(*iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error) {
			return nil, errors.New("AccessDenied: not authorized to perform iam:TagOpenIDConnectProvider")
		},
	}

	out, err := newTestAWS(t, f).ensureProvider(context.Background())
	if err != nil {
		t.Fatalf("a refused tag must not fail the connection: %v", err)
	}
	if out != ProviderCreated {
		t.Fatalf("out = %v", out)
	}
}

func TestEnsureProviderTagsOneThatPredatesTheOwnershipTag(t *testing.T) {
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
		tagOIDCProvider: func(*iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error) {
			return &iam.TagOpenIDConnectProviderOutput{}, nil
		},
	}

	if _, err := newTestAWS(t, f).ensureProvider(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(f.calls, "TagOpenIDConnectProvider") {
		t.Fatalf("converging an existing provider must tag it, calls = %v", f.calls)
	}
}
