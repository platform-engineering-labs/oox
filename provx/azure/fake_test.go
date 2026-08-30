package azure

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// onePage builds a single-page runtime.Pager serving exactly one page (or a
// fetch error), matching how the real SDK pagers are consumed by this
// package's for pager.More() { pager.NextPage(ctx) } loops.
func onePage[T any](page T, err error) *runtime.Pager[T] {
	done := false
	return runtime.NewPager(runtime.PagingHandler[T]{
		More: func(T) bool { return !done },
		Fetcher: func(context.Context, *T) (T, error) {
			done = true
			if err != nil {
				var zero T
				return zero, err
			}
			return page, nil
		},
	})
}

const (
	testSubscriptionID = "11111111-1111-1111-1111-111111111111"
	testAzTenantID     = "22222222-2222-2222-2222-222222222222"
	testFormaeTenantID = "t"
	testInstallationID = "i"
	testResourceGroup  = "formae-ai"
	testLocation       = "eastus"
)

// newTestAzure builds an Azure wired to the given fakes. Any seam left nil
// fails the test the moment the code under test reaches for it, which is
// what proves a refused operation touched nothing beyond what it read.
func newTestAzure(t *testing.T, rg resourceGroupsAPI, ids userAssignedIdentitiesAPI, fed federatedIdentityCredentialsAPI, roles roleAssignmentsAPI, subs subscriptionsAPI) *Azure {
	t.Helper()
	return newWithClients(discardLogger(), testSubscriptionID, testAzTenantID, testFormaeTenantID, testInstallationID, testResourceGroup, testLocation,
		rg, ids, fed, roles, subs)
}

// ---------------------------------------------------------------------------
// fakeResourceGroups
// ---------------------------------------------------------------------------

type fakeResourceGroups struct {
	t     *testing.T
	calls []string

	get            func(name string) (armresources.ResourceGroupsClientGetResponse, error)
	createOrUpdate func(name string, params armresources.ResourceGroup) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error)
}

func (f *fakeResourceGroups) Get(_ context.Context, name string, _ *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "Get")
	if f.get == nil {
		f.t.Fatal("unexpected call ResourceGroups.Get")
	}
	return f.get(name)
}

func (f *fakeResourceGroups) CreateOrUpdate(_ context.Context, name string, params armresources.ResourceGroup, _ *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "CreateOrUpdate")
	if f.createOrUpdate == nil {
		f.t.Fatal("unexpected call ResourceGroups.CreateOrUpdate")
	}
	return f.createOrUpdate(name, params)
}

// ---------------------------------------------------------------------------
// fakeIdentities
// ---------------------------------------------------------------------------

type fakeIdentities struct {
	t     *testing.T
	calls []string

	get            func(name string) (armmsi.UserAssignedIdentitiesClientGetResponse, error)
	createOrUpdate func(name string, params armmsi.Identity) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error)
	del            func(name string) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error)
}

func (f *fakeIdentities) Get(_ context.Context, _, name string, _ *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "Get")
	if f.get == nil {
		f.t.Fatal("unexpected call Identities.Get")
	}
	return f.get(name)
}

func (f *fakeIdentities) CreateOrUpdate(_ context.Context, _, name string, params armmsi.Identity, _ *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "CreateOrUpdate")
	if f.createOrUpdate == nil {
		f.t.Fatal("unexpected call Identities.CreateOrUpdate")
	}
	return f.createOrUpdate(name, params)
}

func (f *fakeIdentities) Delete(_ context.Context, _, name string, _ *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "Delete")
	if f.del == nil {
		f.t.Fatal("unexpected call Identities.Delete")
	}
	return f.del(name)
}

// ---------------------------------------------------------------------------
// fakeFederatedCreds
// ---------------------------------------------------------------------------

type fakeFederatedCreds struct {
	t     *testing.T
	calls []string

	list           []*armmsi.FederatedIdentityCredential
	listErr        error
	createOrUpdate func(name string, params armmsi.FederatedIdentityCredential) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error)
}

func (f *fakeFederatedCreds) NewListPager(_, _ string, _ *armmsi.FederatedIdentityCredentialsClientListOptions) *runtime.Pager[armmsi.FederatedIdentityCredentialsClientListResponse] {
	f.calls = append(f.calls, "List")
	return onePage(armmsi.FederatedIdentityCredentialsClientListResponse{
		FederatedIdentityCredentialsListResult: armmsi.FederatedIdentityCredentialsListResult{Value: f.list},
	}, f.listErr)
}

func (f *fakeFederatedCreds) CreateOrUpdate(_ context.Context, _, _, name string, params armmsi.FederatedIdentityCredential, _ *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "CreateOrUpdate")
	if f.createOrUpdate == nil {
		f.t.Fatal("unexpected call FederatedCreds.CreateOrUpdate")
	}
	return f.createOrUpdate(name, params)
}

// ---------------------------------------------------------------------------
// fakeRoleAssignments
// ---------------------------------------------------------------------------

type fakeRoleAssignments struct {
	t     *testing.T
	calls []string

	create       func(scope, name string, params armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error)
	listForScope []*armauthorization.RoleAssignment
	listErr      error
	deleteByID   func(id string) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error)
}

func (f *fakeRoleAssignments) Create(_ context.Context, scope, name string, params armauthorization.RoleAssignmentCreateParameters, _ *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "Create")
	if f.create == nil {
		f.t.Fatal("unexpected call RoleAssignments.Create")
	}
	return f.create(scope, name, params)
}

func (f *fakeRoleAssignments) NewListForScopePager(_ string, _ *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse] {
	f.calls = append(f.calls, "List")
	return onePage(armauthorization.RoleAssignmentsClientListForScopeResponse{
		RoleAssignmentListResult: armauthorization.RoleAssignmentListResult{Value: f.listForScope},
	}, f.listErr)
}

func (f *fakeRoleAssignments) DeleteByID(_ context.Context, id string, _ *armauthorization.RoleAssignmentsClientDeleteByIDOptions) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
	f.t.Helper()
	f.calls = append(f.calls, "DeleteByID")
	if f.deleteByID == nil {
		f.t.Fatal("unexpected call RoleAssignments.DeleteByID")
	}
	return f.deleteByID(id)
}

// ---------------------------------------------------------------------------
// fakeSubscriptions
// ---------------------------------------------------------------------------

type fakeSubscriptions struct {
	t   *testing.T
	get func(subscriptionID string) (armsubscription.SubscriptionsClientGetResponse, error)
}

func (f *fakeSubscriptions) Get(_ context.Context, subscriptionID string, _ *armsubscription.SubscriptionsClientGetOptions) (armsubscription.SubscriptionsClientGetResponse, error) {
	f.t.Helper()
	if f.get == nil {
		f.t.Fatal("unexpected call Subscriptions.Get")
	}
	return f.get(subscriptionID)
}
