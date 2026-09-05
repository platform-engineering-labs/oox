package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// ProviderOutcome reports what ensureProvider did.
type ProviderOutcome string

const (
	ProviderCreated ProviderOutcome = "created"
	ProviderExisted ProviderOutcome = "existed"
)

const stsAudience = "sts.amazonaws.com"

func (a *AWS) providerArn() string {
	return "arn:aws:iam::" + a.accountID + ":oidc-provider/" + a.issuer.Host()
}

// ensureProvider creates the OIDC provider for the pinned issuer, or
// validates an existing one: its URL must match the pinned issuer
// (anything else is a conflict, not ours to converge) and the STS
// audience is added to its client id list when missing.
func (a *AWS) ensureProvider(ctx context.Context) (ProviderOutcome, error) {
	_, err := a.iam.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{
		Url: aws.String(a.issuer.URL()),
		ClientIDList: []string{
			stsAudience,
		},
	})
	if err == nil {
		a.logger.Info("created: oidc connect provider")
		a.tagProvider(ctx)
		return ProviderCreated, nil
	}

	var alreadyExistsErr *types.EntityAlreadyExistsException
	if !errors.As(err, &alreadyExistsErr) {
		return "", fmt.Errorf("create openId connect provider failed: %w", err)
	}

	got, err := a.iam.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(a.providerArn()),
	})
	if err != nil {
		return "", &ProviderConflictError{Reason: "could not read the existing provider", Cause: err}
	}

	// IAM stores the provider Url scheme-less.
	if aws.ToString(got.Url) != a.issuer.Host() {
		return "", &ProviderConflictError{Reason: "provider URL differs from the pinned issuer"}
	}

	if !slices.Contains(got.ClientIDList, stsAudience) {
		_, err := a.iam.AddClientIDToOpenIDConnectProvider(ctx, &iam.AddClientIDToOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(a.providerArn()),
			ClientID:                 aws.String(stsAudience),
		})
		if err != nil {
			return "", &ProviderConflictError{Reason: "could not add the STS audience to the existing provider", Cause: err}
		}
		a.logger.Info("converged: oidc connect provider audience")
	}

	a.tagProvider(ctx)

	a.logger.Info("exists: oidc connect provider")
	return ProviderExisted, nil
}

// tagProvider marks the provider as formae's own so discovery leaves it alone.
//
// It rides its own request rather than the create's Tags field on purpose: the
// create has never needed iam:TagOpenIDConnectProvider, and requiring it there
// would break connect for callers it works for today. For the same reason a
// refusal is logged and swallowed. An untagged provider is the state every
// account is already in, so degrading to it costs nothing, while failing the
// connect over a marker would cost the connection itself.
//
// It runs on the converge path too, which is what carries the tag to providers
// created before this existed.
func (a *AWS) tagProvider(ctx context.Context) {
	_, err := a.iam.TagOpenIDConnectProvider(ctx, &iam.TagOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(a.providerArn()),
		Tags: []types.Tag{
			{Key: aws.String(tagOwned), Value: aws.String(tagOwnedValue)},
		},
	})
	if err != nil {
		a.logger.Warn("could not tag the oidc connect provider as formae-owned; "+
			"it stays visible to discovery", "error", err)
	}
}

func (a *AWS) deleteProvider(ctx context.Context) error {
	_, err := a.iam.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(a.providerArn()),
	})
	if err != nil {
		var noSuchEntityErr *types.NoSuchEntityException
		if errors.As(err, &noSuchEntityErr) {
			a.logger.Info("already deleted: oidc connect provider")
			return nil
		}
		return err
	}

	a.logger.Info("deleted: oidc connect provider")

	return nil
}
