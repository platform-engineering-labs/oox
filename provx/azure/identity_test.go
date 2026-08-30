package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	oidcazure "github.com/platform-engineering-labs/oox/oidcx/azure"
)

func notFoundErr() error {
	return &azcore.ResponseError{StatusCode: 404, ErrorCode: "ResourceGroupNotFound"}
}

func TestEnsureResourceGroupRefusesADifferentLocation(t *testing.T) {
	rg := &fakeResourceGroups{t: t, get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
		return armresources.ResourceGroupsClientGetResponse{ResourceGroup: armresources.ResourceGroup{
			Location: to.Ptr("westus"),
		}}, nil
	}}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	err := az.ensureResourceGroup(context.Background())

	var mismatch *LocationMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want LocationMismatchError, got %v", err)
	}
	if mismatch.Existing != "westus" || mismatch.Requested != testLocation {
		t.Fatalf("mismatch = %+v", mismatch)
	}
	for _, c := range rg.calls {
		if c == "CreateOrUpdate" {
			t.Fatal("a location mismatch must not converge; no create call may be submitted")
		}
	}
}

func TestEnsureResourceGroupConvergesOnAMatchingLocation(t *testing.T) {
	rg := &fakeResourceGroups{t: t, get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
		return armresources.ResourceGroupsClientGetResponse{ResourceGroup: armresources.ResourceGroup{
			Location: to.Ptr(testLocation),
		}}, nil
	}}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	if err := az.ensureResourceGroup(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, c := range rg.calls {
		if c == "CreateOrUpdate" {
			t.Fatal("an already-matching resource group must not be written to")
		}
	}
}

func TestAnAdoptedResourceGroupKeepsItsTags(t *testing.T) {
	rg := &fakeResourceGroups{t: t, get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
		return armresources.ResourceGroupsClientGetResponse{ResourceGroup: armresources.ResourceGroup{
			Location: to.Ptr(testLocation),
			Tags:     map[string]*string{"team": to.Ptr("someone-else")},
		}}, nil
	}}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	if err := az.ensureResourceGroup(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, c := range rg.calls {
		if c == "CreateOrUpdate" {
			t.Fatal("adopting a resource group must not write to it, so its tags cannot be touched")
		}
	}
}

func TestEnsureResourceGroupCreatesAndTagsAMissingGroup(t *testing.T) {
	var created armresources.ResourceGroup
	rg := &fakeResourceGroups{t: t,
		get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
			return armresources.ResourceGroupsClientGetResponse{}, notFoundErr()
		},
		createOrUpdate: func(name string, params armresources.ResourceGroup) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
			if name != testResourceGroup {
				t.Fatalf("name = %q", name)
			}
			created = params
			return armresources.ResourceGroupsClientCreateOrUpdateResponse{ResourceGroup: params}, nil
		},
	}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	if err := az.ensureResourceGroup(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if deref(created.Location) != testLocation {
		t.Fatalf("Location = %q", deref(created.Location))
	}
	if deref(created.Tags[ownerTagKey]) != ownerTagValue {
		t.Fatalf("Tags = %v; a group we create must be tagged owned", created.Tags)
	}
}

func TestEnsureIdentityCreatesAMissingIdentity(t *testing.T) {
	var created armmsi.Identity
	ids := &fakeIdentities{t: t,
		get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
			return armmsi.UserAssignedIdentitiesClientGetResponse{}, notFoundErr()
		},
		createOrUpdate: func(name string, params armmsi.Identity) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
			if name != identityPrefix+testInstallationID {
				t.Fatalf("name = %q", name)
			}
			created = params
			return armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse{Identity: params}, nil
		},
	}
	az := newTestAzure(t, nil, ids, nil, nil, nil)

	if _, err := az.ensureIdentity(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if deref(created.Location) != testLocation {
		t.Fatalf("Location = %q", deref(created.Location))
	}
	if deref(created.Tags[ownerTagKey]) != ownerTagValue {
		t.Fatalf("Tags = %v; an identity we create must be tagged owned", created.Tags)
	}
}

func TestEnsureIdentityAdoptsAnExistingIdentity(t *testing.T) {
	ids := &fakeIdentities{t: t,
		get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
			return armmsi.UserAssignedIdentitiesClientGetResponse{Identity: armmsi.Identity{
				Properties: &armmsi.UserAssignedIdentityProperties{ClientID: to.Ptr("client-1")},
			}}, nil
		},
		// createOrUpdate nil: adopting an existing identity must not write to it.
	}
	az := newTestAzure(t, nil, ids, nil, nil, nil)

	got, err := az.ensureIdentity(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.Properties == nil || deref(got.Properties.ClientID) != "client-1" {
		t.Fatalf("got = %+v", got)
	}
}

// fedCred builds a federated identity credential as the fake ARM server
// would return it: a name plus the three properties Classify cares about.
func fedCred(name, issuer, subject string, audiences ...string) *armmsi.FederatedIdentityCredential {
	auds := make([]*string, len(audiences))
	for i, a := range audiences {
		auds[i] = to.Ptr(a)
	}
	return &armmsi.FederatedIdentityCredential{
		Name: to.Ptr(name),
		Properties: &armmsi.FederatedIdentityCredentialProperties{
			Issuer:    to.Ptr(issuer),
			Subject:   to.Ptr(subject),
			Audiences: auds,
		},
	}
}

func ourIssuer(az *Azure) string  { return az.issuer }
func ourSubject(az *Azure) string { return az.subject }

func TestAdoptionAcceptsExactlyOurCredential(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	fed := &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, ourIssuer(az), ourSubject(az), oidcazure.Audience),
	}}
	az.federatedCreds = fed
	// createOrUpdate nil: an already-converged credential must not be written to.

	if err := az.ensureFederatedCredential(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestAdoptionRefusesAWrongIssuer(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.federatedCreds = &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, "https://evil.example.com", ourSubject(az), oidcazure.Audience),
	}}

	err := az.ensureFederatedCredential(context.Background())
	var notOurs *IdentityNotOursError
	if !errors.As(err, &notOurs) {
		t.Fatalf("want IdentityNotOursError, got %v", err)
	}
}

func TestAdoptionRefusesAWrongSubject(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.federatedCreds = &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, ourIssuer(az), "fai:other/x", oidcazure.Audience),
	}}

	err := az.ensureFederatedCredential(context.Background())
	var notOurs *IdentityNotOursError
	if !errors.As(err, &notOurs) {
		t.Fatalf("want IdentityNotOursError, got %v", err)
	}
}

func TestAdoptionRefusesAnIdentityCarryingAForeignCredential(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	fed := &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, ourIssuer(az), ourSubject(az), oidcazure.Audience),
		fedCred("someone-elses-cred", "https://evil.example.com", "not-ours", "some-other-audience"),
	}}
	az.federatedCreds = fed
	// createOrUpdate nil: a refused adoption must not write to the identity.

	err := az.ensureFederatedCredential(context.Background())
	var notOurs *IdentityNotOursError
	if !errors.As(err, &notOurs) {
		t.Fatalf("want IdentityNotOursError, got %v", err)
	}
}

func TestIdentityNotOursNamesWhatToRemove(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.federatedCreds = &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, ourIssuer(az), ourSubject(az), oidcazure.Audience),
		fedCred("someone-elses-cred", "https://evil.example.com", "not-ours", "some-other-audience"),
	}}

	err := az.ensureFederatedCredential(context.Background())
	if err == nil || !strings.Contains(err.Error(), "someone-elses-cred") {
		t.Fatalf("message must name the unexpected credential, got %v", err)
	}
	if !strings.Contains(err.Error(), "remove") {
		t.Fatalf("message must say what to do, got %v", err)
	}
}

func TestEnsureFederatedCredentialCreatesWhenNoneExist(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	var got armmsi.FederatedIdentityCredential
	az.federatedCreds = &fakeFederatedCreds{t: t,
		createOrUpdate: func(name string, params armmsi.FederatedIdentityCredential) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
			if name != credentialName {
				t.Fatalf("name = %q", name)
			}
			got = params
			return armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse{FederatedIdentityCredential: params}, nil
		},
	}

	if err := az.ensureFederatedCredential(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if deref(got.Properties.Issuer) != ourIssuer(az) || deref(got.Properties.Subject) != ourSubject(az) {
		t.Fatalf("got = %+v", got.Properties)
	}
}
