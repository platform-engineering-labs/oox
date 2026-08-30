package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// tokenAudience is the OAuth audience Entra workload identity federation
// expects for a client-assertion exchange. It must equal the Audience
// constant the root oox module's Azure client-credential package declares
// for the other half of this same exchange, but the two are deliberately
// not sharing code: that package lives in the root module, and provx is
// consumed standalone (by formae, which pins its own go toolchain) - an
// import across that module edge would drag the root module's newer go
// directive into provx and force every consumer onto it. Each side pins the
// identical literal in its own tests instead - see the golden test in
// identity_test.go - so a change to one side that drifts from the other
// fails loudly rather than silently.
const tokenAudience = "api://AzureADTokenExchange"

// ensureResourceGroup converges the target resource group: create it, tagged
// as ours, when it does not exist; adopt it unmodified when it does.
//
// An adopted group's tags are left exactly as found. Delete never removes the
// resource group (it may hold other installations' identities), so tagging
// one we did not create would claim an ownership we can never act on, and a
// group whose location does not match the request cannot be converged at
// all: location is immutable on an Azure resource group.
func (az *Azure) ensureResourceGroup(ctx context.Context) error {
	existing, err := az.resourceGroups.Get(ctx, az.resourceGroup, nil)
	if err == nil {
		if got := deref(existing.Location); got != az.location {
			return &LocationMismatchError{ResourceGroup: az.resourceGroup, Existing: got, Requested: az.location}
		}
		return nil
	}
	if armStatusCode(err) != 404 {
		return Classify(err, opResourceGroup)
	}

	_, err = az.resourceGroups.CreateOrUpdate(ctx, az.resourceGroup, armresources.ResourceGroup{
		Location: to.Ptr(az.location),
		Tags:     map[string]*string{ownerTagKey: to.Ptr(ownerTagValue)},
	}, nil)
	return Classify(err, opResourceGroup)
}

// ensureIdentity converges the target managed identity: create it, tagged as
// ours, when it does not exist; adopt it unmodified when it does. Whether an
// adopted identity is safe to actually use is decided separately, by
// ensureFederatedCredential: the identity's own tags say nothing about that.
func (az *Azure) ensureIdentity(ctx context.Context) (armmsi.Identity, error) {
	existing, err := az.identities.Get(ctx, az.resourceGroup, az.identityName(), nil)
	if err == nil {
		return existing.Identity, nil
	}
	if armStatusCode(err) != 404 {
		return armmsi.Identity{}, Classify(err, opManagedIdentity)
	}

	created, err := az.identities.CreateOrUpdate(ctx, az.resourceGroup, az.identityName(), armmsi.Identity{
		Location: to.Ptr(az.location),
		Tags:     map[string]*string{ownerTagKey: to.Ptr(ownerTagValue)},
	}, nil)
	if err != nil {
		return armmsi.Identity{}, Classify(err, opManagedIdentity)
	}
	return created.Identity, nil
}

// wantAudiences is the exact audience list every federated credential this
// package creates or adopts must carry.
func wantAudiences() []string { return []string{tokenAudience} }

// ensureFederatedCredential converges the identity's federated identity
// credential.
//
// A federated credential grants near-owner access to whoever can present a
// token matching its issuer, subject and audience, so adoption is strict
// rather than reconciling: an identity is only ours to use when it carries
// exactly one federated credential and that credential already matches ours
// exactly. Anything else - zero credentials aside, which is simply a fresh
// identity to finish setting up - is refused rather than patched, because
// patching would either silently take over a credential someone else
// depends on, or silently leave a second, foreign credential in place that
// can still assume the identity.
func (az *Azure) ensureFederatedCredential(ctx context.Context) error {
	creds, err := az.listFederatedCredentials(ctx)
	if err != nil {
		return Classify(err, opManagedIdentity)
	}

	if len(creds) == 0 {
		_, err := az.federatedCreds.CreateOrUpdate(ctx, az.resourceGroup, az.identityName(), credentialName, armmsi.FederatedIdentityCredential{
			Properties: &armmsi.FederatedIdentityCredentialProperties{
				Issuer:    to.Ptr(az.issuer),
				Subject:   to.Ptr(az.subject),
				Audiences: []*string{to.Ptr(tokenAudience)},
			},
		}, nil)
		return Classify(err, opManagedIdentity)
	}
	return az.solelyOurs(creds)
}

// verifyFederatedCredential re-checks the same adoption rule
// ensureFederatedCredential enforces, without ever writing: Delete must
// refuse an identity that is not safely ours before removing anything, and
// resolving by deterministic name and deleting whatever sits there would
// destroy a foreign identity occupying that name. Unlike
// ensureFederatedCredential, zero credentials here is also a refusal: by the
// time Delete runs, this installation's own Create should have left exactly
// one, so their absence means this is not the identity formae created.
func (az *Azure) verifyFederatedCredential(ctx context.Context) error {
	creds, err := az.listFederatedCredentials(ctx)
	if err != nil {
		return Classify(err, opManagedIdentity)
	}
	return az.solelyOurs(creds)
}

// solelyOurs reports whether creds is exactly the one federated credential
// this installation would create, returning an *IdentityNotOursError naming
// the offending credential (or, when none of them individually disagree,
// the count) otherwise.
func (az *Azure) solelyOurs(creds []*armmsi.FederatedIdentityCredential) error {
	for _, c := range creds {
		if !az.matchesOurs(c) {
			return &IdentityNotOursError{Name: deref(c.Name), Reason: az.mismatchReason(c)}
		}
	}
	if len(creds) == 1 {
		return nil
	}
	names := make([]string, len(creds))
	for i, c := range creds {
		names[i] = deref(c.Name)
	}
	name := strings.Join(names, ", ")
	if name == "" {
		name = "(none)"
	}
	return &IdentityNotOursError{
		Name:   name,
		Reason: fmt.Sprintf("%d federated credentials present, expected exactly 1", len(creds)),
	}
}

// listFederatedCredentials enumerates every federated credential on this
// installation's identity, across pagination.
func (az *Azure) listFederatedCredentials(ctx context.Context) ([]*armmsi.FederatedIdentityCredential, error) {
	var all []*armmsi.FederatedIdentityCredential
	pager := az.federatedCreds.NewListPager(az.resourceGroup, az.identityName(), nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
	}
	return all, nil
}

// matchesOurs reports whether an existing federated credential's issuer,
// subject and audiences are exactly what this installation would create.
func (az *Azure) matchesOurs(c *armmsi.FederatedIdentityCredential) bool {
	if c == nil || c.Properties == nil {
		return false
	}
	p := c.Properties
	return deref(p.Issuer) == az.issuer &&
		deref(p.Subject) == az.subject &&
		sameStrings(derefAll(p.Audiences), wantAudiences())
}

// mismatchReason names every field of an existing credential that differs
// from what this installation would create, so a refusal is actionable
// rather than a dead end.
func (az *Azure) mismatchReason(c *armmsi.FederatedIdentityCredential) string {
	var issuer, subject string
	var audiences []string
	if c.Properties != nil {
		issuer = deref(c.Properties.Issuer)
		subject = deref(c.Properties.Subject)
		audiences = derefAll(c.Properties.Audiences)
	}

	var diffs []string
	if issuer != az.issuer {
		diffs = append(diffs, fmt.Sprintf("issuer is %q, want %q", issuer, az.issuer))
	}
	if subject != az.subject {
		diffs = append(diffs, fmt.Sprintf("subject is %q, want %q", subject, az.subject))
	}
	if want := wantAudiences(); !sameStrings(audiences, want) {
		diffs = append(diffs, fmt.Sprintf("audiences are %v, want %v", audiences, want))
	}
	return strings.Join(diffs, "; ")
}

// derefAll dereferences every pointer in a slice, in order.
func derefAll(ptrs []*string) []string {
	out := make([]string, len(ptrs))
	for i, p := range ptrs {
		out[i] = deref(p)
	}
	return out
}
