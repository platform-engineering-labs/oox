package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	oidcazure "github.com/platform-engineering-labs/oox/oidcx/azure"
	"github.com/platform-engineering-labs/oox/provx"
)

func TestCreateReturnsTheRegistrationCoordinates(t *testing.T) {
	const wantIdentityID = "/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testResourceGroup +
		"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + identityPrefix + testInstallationID
	const wantClientID = "client-1"
	const wantPrincipalID = "principal-1"

	rg := &fakeResourceGroups{t: t,
		get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
			return armresources.ResourceGroupsClientGetResponse{}, notFoundErr()
		},
		createOrUpdate: func(string, armresources.ResourceGroup) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
			return armresources.ResourceGroupsClientCreateOrUpdateResponse{}, nil
		},
	}
	ids := &fakeIdentities{t: t,
		get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
			return armmsi.UserAssignedIdentitiesClientGetResponse{}, notFoundErr()
		},
		createOrUpdate: func(string, armmsi.Identity) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
			return armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse{Identity: armmsi.Identity{
				ID: to.Ptr(wantIdentityID),
				Properties: &armmsi.UserAssignedIdentityProperties{
					// ClientID and PrincipalID are deliberately different
					// values: a test that used the same string for both
					// would not catch them being swapped.
					ClientID:    to.Ptr(wantClientID),
					PrincipalID: to.Ptr(wantPrincipalID),
				},
			}}, nil
		},
	}
	fed := &fakeFederatedCreds{t: t,
		createOrUpdate: func(string, armmsi.FederatedIdentityCredential) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
			return armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse{}, nil
		},
	}
	roles := &fakeRoleAssignments{t: t,
		create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
	}
	az := newTestAzure(t, rg, ids, fed, roles, nil)

	res, err := az.Create(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := &Result{
		TenantID:      testAzTenantID,
		ClientID:      wantClientID,
		PrincipalID:   wantPrincipalID,
		IdentityID:    wantIdentityID,
		ResourceGroup: testResourceGroup,
		Location:      testLocation,
	}
	if *res != *want {
		t.Fatalf("Create() = %+v, want %+v", res, want)
	}
}

// identityStore fakes the identities client with a real map, so a test can
// drive two installations' identities through the same resource group and
// check that deleting one leaves the other standing.
type identityStore struct {
	t          *testing.T
	identities map[string]armmsi.Identity
}

func (s *identityStore) fake() *fakeIdentities {
	return &fakeIdentities{t: s.t,
		get: func(name string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
			id, ok := s.identities[name]
			if !ok {
				return armmsi.UserAssignedIdentitiesClientGetResponse{}, notFoundErr()
			}
			return armmsi.UserAssignedIdentitiesClientGetResponse{Identity: id}, nil
		},
		del: func(name string) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error) {
			delete(s.identities, name)
			return armmsi.UserAssignedIdentitiesClientDeleteResponse{}, nil
		},
	}
}

func TestDeleteRemovesOnlyThisInstallationsIdentity(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.installationID = "installation-a"
	az.subject = provx.Subject(az.formaeTenantID, az.installationID)

	other := identityPrefix + "installation-b"
	store := &identityStore{t: t, identities: map[string]armmsi.Identity{
		az.identityName(): {Properties: &armmsi.UserAssignedIdentityProperties{PrincipalID: to.Ptr("principal-a")}},
		other:             {Properties: &armmsi.UserAssignedIdentityProperties{PrincipalID: to.Ptr("principal-b")}},
	}}
	az.identities = store.fake()
	az.federatedCreds = &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred(credentialName, az.issuer, az.subject, oidcazure.Audience),
	}}
	az.roleAssignments = &fakeRoleAssignments{t: t, listForScope: nil}
	// az.resourceGroups is left nil: Delete has no resource-group method to
	// call in the first place, which is what proves it cannot remove one.

	if err := az.Delete(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, ok := store.identities[az.identityName()]; ok {
		t.Fatal("this installation's identity must be deleted")
	}
	if _, ok := store.identities[other]; !ok {
		t.Fatal("the other installation's identity must survive")
	}
}

func TestDeleteRefusesAnIdentityThatIsNotOurs(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.identities = &fakeIdentities{t: t, get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
		return armmsi.UserAssignedIdentitiesClientGetResponse{Identity: armmsi.Identity{
			Properties: &armmsi.UserAssignedIdentityProperties{PrincipalID: to.Ptr("someone-elses-principal")},
		}}, nil
	}}
	// del left nil: a refused Delete must not remove the identity.
	az.federatedCreds = &fakeFederatedCreds{t: t, list: []*armmsi.FederatedIdentityCredential{
		fedCred("foreign", "https://evil.example.com", "not-ours", "some-other-audience"),
	}}
	// roleAssignments left nil: a refused Delete must not touch role assignments either.

	err := az.Delete(context.Background())
	var notOurs *IdentityNotOursError
	if !errors.As(err, &notOurs) {
		t.Fatalf("want IdentityNotOursError, got %v", err)
	}
}

func TestDeleteOfAnAlreadyMissingIdentityIsANoOp(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	az.identities = &fakeIdentities{t: t, get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
		return armmsi.UserAssignedIdentitiesClientGetResponse{}, notFoundErr()
	}}
	if err := az.Delete(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifySubscriptionReturnsThePinnedTenantID(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, &fakeSubscriptions{t: t, get: func(string) (armsubscription.SubscriptionsClientGetResponse, error) {
		return armsubscription.SubscriptionsClientGetResponse{}, nil
	}})

	got, err := az.VerifySubscription(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != testAzTenantID {
		t.Fatalf("got = %q, want the pinned tenant %q", got, testAzTenantID)
	}
}

func TestVerifySubscriptionClassifiesFailure(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, &fakeSubscriptions{t: t, get: func(string) (armsubscription.SubscriptionsClientGetResponse, error) {
		return armsubscription.SubscriptionsClientGetResponse{}, &azcore.ResponseError{ErrorCode: "AuthorizationFailed", StatusCode: 403}
	}})

	_, err := az.VerifySubscription(context.Background())
	var denied *PermissionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("want PermissionDeniedError, got %v", err)
	}
}
