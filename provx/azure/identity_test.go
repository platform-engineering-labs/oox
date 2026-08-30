package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
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
