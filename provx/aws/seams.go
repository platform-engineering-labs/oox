package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamAPI interface {
	CreateOpenIDConnectProvider(ctx context.Context, in *iam.CreateOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.CreateOpenIDConnectProviderOutput, error)
	GetOpenIDConnectProvider(ctx context.Context, in *iam.GetOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error)
	AddClientIDToOpenIDConnectProvider(ctx context.Context, in *iam.AddClientIDToOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.AddClientIDToOpenIDConnectProviderOutput, error)
	DeleteOpenIDConnectProvider(ctx context.Context, in *iam.DeleteOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.DeleteOpenIDConnectProviderOutput, error)
	CreateRole(ctx context.Context, in *iam.CreateRoleInput, opts ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	GetRole(ctx context.Context, in *iam.GetRoleInput, opts ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	DeleteRole(ctx context.Context, in *iam.DeleteRoleInput, opts ...func(*iam.Options)) (*iam.DeleteRoleOutput, error)
	ListRoleTags(ctx context.Context, in *iam.ListRoleTagsInput, opts ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
	TagRole(ctx context.Context, in *iam.TagRoleInput, opts ...func(*iam.Options)) (*iam.TagRoleOutput, error)
	TagOpenIDConnectProvider(ctx context.Context, in *iam.TagOpenIDConnectProviderInput, opts ...func(*iam.Options)) (*iam.TagOpenIDConnectProviderOutput, error)
	UpdateAssumeRolePolicy(ctx context.Context, in *iam.UpdateAssumeRolePolicyInput, opts ...func(*iam.Options)) (*iam.UpdateAssumeRolePolicyOutput, error)
	AttachRolePolicy(ctx context.Context, in *iam.AttachRolePolicyInput, opts ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(ctx context.Context, in *iam.DetachRolePolicyInput, opts ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	PutRolePolicy(ctx context.Context, in *iam.PutRolePolicyInput, opts ...func(*iam.Options)) (*iam.PutRolePolicyOutput, error)
	ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	DeleteRolePolicy(ctx context.Context, in *iam.DeleteRolePolicyInput, opts ...func(*iam.Options)) (*iam.DeleteRolePolicyOutput, error)
}
