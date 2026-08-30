package azure

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

func armErr(code string) error {
	return &azcore.ResponseError{ErrorCode: code, StatusCode: 409}
}

// manualClock lets a test drive the propagation retry loop through a full
// timeout without waiting on a real one: Sleep advances the clock instead of
// blocking.
type manualClock struct{ t time.Time }

func (c *manualClock) Now() time.Time { return c.t }
func (c *manualClock) Sleep(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

const testPrincipalID = "44444444-4444-4444-4444-444444444444"

func TestBothRolesAreSubmittedAtSubscriptionScope(t *testing.T) {
	var gotScopes, gotRoleDefIDs []string
	var gotPrincipalTypes []armauthorization.PrincipalType
	roles := &fakeRoleAssignments{t: t, create: func(scope, _ string, params armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		gotScopes = append(gotScopes, scope)
		gotRoleDefIDs = append(gotRoleDefIDs, deref(params.Properties.RoleDefinitionID))
		gotPrincipalTypes = append(gotPrincipalTypes, *params.Properties.PrincipalType)
		return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
	}}
	az := newTestAzure(t, nil, nil, nil, roles, nil)

	if err := az.ensureRoleAssignments(context.Background(), testPrincipalID); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(gotScopes) != 2 {
		t.Fatalf("want exactly 2 Create calls, got %d", len(gotScopes))
	}
	for _, s := range gotScopes {
		if s != az.scope() {
			t.Fatalf("scope = %q, want %q", s, az.scope())
		}
	}
	for _, pt := range gotPrincipalTypes {
		if pt != armauthorization.PrincipalTypeServicePrincipal {
			t.Fatalf("PrincipalType = %v", pt)
		}
	}
	wantRoleDefIDs := map[string]bool{
		az.roleDefinitionID(contributorRoleID):     false,
		az.roleDefinitionID(userAccessAdminRoleID): false,
	}
	for _, id := range gotRoleDefIDs {
		if _, ok := wantRoleDefIDs[id]; !ok {
			t.Fatalf("unexpected role definition id %q", id)
		}
		wantRoleDefIDs[id] = true
	}
	for id, seen := range wantRoleDefIDs {
		if !seen {
			t.Fatalf("role %q was never assigned", id)
		}
	}

	// Re-run against a fake reporting the assignment already exists: zero
	// further calls, because both were already granted.
	calls := 0
	roles2 := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		calls++
		return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("RoleAssignmentExists")
	}}
	az2 := newTestAzure(t, nil, nil, nil, roles2, nil)
	if err := az2.ensureRoleAssignments(context.Background(), testPrincipalID); err != nil {
		t.Fatalf("err = %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected one Create attempt per role (both reporting already-exists), got %d", calls)
	}
}

func TestAnEquivalentAssignmentUnderAnotherNameIsTreatedAsSuccess(t *testing.T) {
	roles := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("RoleAssignmentExists")
	}}
	az := newTestAzure(t, nil, nil, nil, roles, nil)

	if err := az.ensureRoleAssignments(context.Background(), testPrincipalID); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestRoleAssignmentForbiddenNamesTheRequiredRole(t *testing.T) {
	roles := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("AuthorizationFailed")
	}}
	az := newTestAzure(t, nil, nil, nil, roles, nil)

	err := az.ensureRoleAssignments(context.Background(), testPrincipalID)
	var forbidden *RoleAssignmentForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("want RoleAssignmentForbiddenError, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "Owner") || !strings.Contains(msg, "User Access Administrator") {
		t.Fatalf("message must name the required role, got %q", msg)
	}
}

func TestPrincipalPropagationIsRetriedThenGivesUp(t *testing.T) {
	t.Run("succeeds after two retries", func(t *testing.T) {
		attempts := 0
		roles := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			attempts++
			if attempts <= 2 {
				return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("PrincipalNotFound")
			}
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		}}
		az := newTestAzure(t, nil, nil, nil, roles, nil)
		clock := &manualClock{t: time.Now()}
		az.now = clock.Now
		az.sleep = clock.Sleep

		if err := az.ensureRoleAssignment(context.Background(), testPrincipalID, contributorRoleID); err != nil {
			t.Fatalf("err = %v", err)
		}
		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3 (2 failures then success)", attempts)
		}
	})

	t.Run("gives up naming the timeout", func(t *testing.T) {
		roles := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("PrincipalNotFound")
		}}
		az := newTestAzure(t, nil, nil, nil, roles, nil)
		clock := &manualClock{t: time.Now()}
		az.now = clock.Now
		az.sleep = clock.Sleep

		err := az.ensureRoleAssignment(context.Background(), testPrincipalID, contributorRoleID)
		if err == nil || !strings.Contains(err.Error(), spPropagationTimeout.String()) {
			t.Fatalf("err = %v, want it to name the timeout %s", err, spPropagationTimeout)
		}
	})
}

func TestAssignmentNameGoldenVectors(t *testing.T) {
	const (
		scope     = "/subscriptions/11111111-1111-1111-1111-111111111111"
		principal = "33333333-3333-3333-3333-333333333333"
		roleDef1  = "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
		roleDef2  = "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
	)
	if got := assignmentName(scope, principal, roleDef1); got != "bdf9b143-1310-5aec-8a4e-b2ae32d1ee52" {
		t.Fatalf("assignmentName(contributor) = %s, want the pinned golden value", got)
	}
	if got := assignmentName(scope, principal, roleDef2); got != "88a198dd-288b-5bca-a138-93ef6419e12e" {
		t.Fatalf("assignmentName(userAccessAdmin) = %s, want the pinned golden value", got)
	}
}

func TestDeleteRoleAssignmentsOnlyRemovesTheRolesThisPackageGrants(t *testing.T) {
	var deleted []string
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	roles := &fakeRoleAssignments{t: t,
		listForScope: []*armauthorization.RoleAssignment{
			{ID: to.Ptr("/id/1"), Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID: to.Ptr(testPrincipalID), RoleDefinitionID: to.Ptr(az.roleDefinitionID(contributorRoleID))}},
			{ID: to.Ptr("/id/2"), Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID: to.Ptr(testPrincipalID), RoleDefinitionID: to.Ptr(az.roleDefinitionID(userAccessAdminRoleID))}},
			{ID: to.Ptr("/id/3"), Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID: to.Ptr(testPrincipalID), RoleDefinitionID: to.Ptr(az.roleDefinitionID("some-other-role"))}},
			// Same role, a different principal. The server-side $filter is
			// supposed to keep this out of the page in the first place, but
			// this fixture proves the client does not also trust that filter
			// blindly: if it were ever dropped, mistyped, or not honoured by
			// ARM, this is the assignment that would otherwise get deleted
			// out from under someone else.
			{ID: to.Ptr("/id/4"), Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID: to.Ptr("some-other-principal"), RoleDefinitionID: to.Ptr(az.roleDefinitionID(contributorRoleID))}},
		},
		deleteByID: func(id string) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
			deleted = append(deleted, id)
			return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, nil
		},
	}
	az.roleAssignments = roles

	if err := az.deleteRoleAssignments(context.Background(), testPrincipalID); err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(deleted) != 2 || !contains(deleted, "/id/1") || !contains(deleted, "/id/2") {
		t.Fatalf("deleted = %v, want exactly the two roles this package grants for this principal", deleted)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func TestDeleteRoleAssignmentsClassifiesAForbiddenDeletion(t *testing.T) {
	az := newTestAzure(t, nil, nil, nil, nil, nil)
	roles := &fakeRoleAssignments{t: t,
		listForScope: []*armauthorization.RoleAssignment{
			{ID: to.Ptr("/id/1"), Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID: to.Ptr(testPrincipalID), RoleDefinitionID: to.Ptr(az.roleDefinitionID(contributorRoleID))}},
		},
		deleteByID: func(string) (armauthorization.RoleAssignmentsClientDeleteByIDResponse, error) {
			return armauthorization.RoleAssignmentsClientDeleteByIDResponse{}, armErr("AuthorizationFailed")
		},
	}
	az.roleAssignments = roles

	err := az.deleteRoleAssignments(context.Background(), testPrincipalID)
	var forbidden *RoleAssignmentForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("want RoleAssignmentForbiddenError, got %v", err)
	}
}

func TestRoleAssignmentUpdateNotPermittedIsForbiddenOnRoleAssignment(t *testing.T) {
	roles := &fakeRoleAssignments{t: t, create: func(string, string, armauthorization.RoleAssignmentCreateParameters) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		return armauthorization.RoleAssignmentsClientCreateResponse{}, armErr("RoleAssignmentUpdateNotPermitted")
	}}
	az := newTestAzure(t, nil, nil, nil, roles, nil)

	err := az.ensureRoleAssignments(context.Background(), testPrincipalID)
	var forbidden *RoleAssignmentForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("want RoleAssignmentForbiddenError, got %v", err)
	}
}
