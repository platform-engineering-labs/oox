package azure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// TestUnregisteredProviderIsNamedAndNotRegisteredForThem drives
// classification through a real operation - ensuring the managed identity -
// rather than calling Classify directly, so the test also proves that call
// site actually routes its errors through Classify.
func TestUnregisteredProviderIsNamedAndNotRegisteredForThem(t *testing.T) {
	ids := &fakeIdentities{t: t, get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
		return armmsi.UserAssignedIdentitiesClientGetResponse{}, &azcore.ResponseError{
			ErrorCode:  "MissingSubscriptionRegistration",
			StatusCode: 409,
		}
	}}
	az := newTestAzure(t, nil, ids, nil, nil, nil)

	_, err := az.ensureIdentity(context.Background())
	var notRegistered *ProviderNotRegisteredError
	if !errors.As(err, &notRegistered) {
		t.Fatalf("want ProviderNotRegisteredError, got %v", err)
	}
	if notRegistered.Provider != "Microsoft.ManagedIdentity" {
		t.Fatalf("Provider = %q", notRegistered.Provider)
	}
	msg := err.Error()
	if !strings.Contains(msg, "Microsoft.ManagedIdentity") || !strings.Contains(msg, "register") {
		t.Fatalf("message must name the provider and say registration is required, got %q", msg)
	}
	// The fake's createOrUpdate field is nil: reaching it would already fail
	// the test, which is what proves no registration call - there is no such
	// call in this package at all - and no create attempt were made.
}

func TestAWrappedResponseErrorStillClassifies(t *testing.T) {
	rg := &fakeResourceGroups{t: t, get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
		cause := &azcore.ResponseError{ErrorCode: "MissingSubscriptionRegistration", StatusCode: 409}
		return armresources.ResourceGroupsClientGetResponse{}, fmt.Errorf("request failed: %w", cause)
	}}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	err := az.ensureResourceGroup(context.Background())
	var notRegistered *ProviderNotRegisteredError
	if !errors.As(err, &notRegistered) {
		t.Fatalf("want ProviderNotRegisteredError even through a wrapped SDK error, got %v", err)
	}
}

func TestABare403AssertsNoCause(t *testing.T) {
	sentinel := &azcore.ResponseError{StatusCode: 403}
	rg := &fakeResourceGroups{t: t, get: func(string) (armresources.ResourceGroupsClientGetResponse, error) {
		return armresources.ResourceGroupsClientGetResponse{}, sentinel
	}}
	az := newTestAzure(t, rg, nil, nil, nil, nil)

	err := az.ensureResourceGroup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want it to carry the status", err)
	}
	if errors.Is(err, sentinel) {
		t.Fatal("an unrecognised error must not chain back to the raw SDK error")
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("an unrecognised error must carry no cause")
	}
}

func TestPermissionDeniedOnNonRoleAssignmentOperation(t *testing.T) {
	ids := &fakeIdentities{t: t, get: func(string) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
		return armmsi.UserAssignedIdentitiesClientGetResponse{}, &azcore.ResponseError{ErrorCode: "AuthorizationFailed", StatusCode: 403}
	}}
	az := newTestAzure(t, nil, ids, nil, nil, nil)

	err := errorFromEnsureIdentity(t, az)
	var denied *PermissionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("want PermissionDeniedError, got %v", err)
	}
	var forbidden *RoleAssignmentForbiddenError
	if errors.As(err, &forbidden) {
		t.Fatalf("AuthorizationFailed on a non-role-assignment call must not read as RoleAssignmentForbiddenError, got %v", err)
	}
}

func errorFromEnsureIdentity(t *testing.T, az *Azure) error {
	t.Helper()
	_, err := az.ensureIdentity(context.Background())
	return err
}
