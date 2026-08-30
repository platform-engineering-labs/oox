package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/google/uuid"
)

// spPropagationTimeout bounds how long we wait for a freshly created
// service principal to become visible to ARM.
const spPropagationTimeout = 3 * time.Minute

// roleIDs is the fixed set of built-in roles the identity needs at the
// subscription scope: Contributor to manage infrastructure, and User Access
// Administrator because formae itself grants roles as part of that.
var roleIDs = []string{contributorRoleID, userAccessAdminRoleID}

// ensureRoleAssignments grants every role in roleIDs to the identity's
// service principal at the subscription scope. Each is independently
// idempotent, so a re-run that finds some already granted converges without
// error.
func (az *Azure) ensureRoleAssignments(ctx context.Context, principalID string) error {
	for _, roleID := range roleIDs {
		if err := az.ensureRoleAssignment(ctx, principalID, roleID); err != nil {
			return err
		}
	}
	return nil
}

// ensureRoleAssignment grants one role, retrying while ARM cannot yet see
// the principal (replication lag after the identity was just created) and
// treating an equivalent assignment under any other name as success: Azure
// itself answers RoleAssignmentExists for a duplicate principal+scope+role
// tuple regardless of which GUID it was created under.
func (az *Azure) ensureRoleAssignment(ctx context.Context, principalID, roleID string) error {
	scope := az.scope()
	roleDefID := az.roleDefinitionID(roleID)
	name := assignmentName(scope, principalID, roleDefID)

	params := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			PrincipalID:      to.Ptr(principalID),
			RoleDefinitionID: to.Ptr(roleDefID),
			PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
		},
	}

	deadline := az.now().Add(spPropagationTimeout)
	backoff := 2 * time.Second

	for {
		_, err := az.roleAssignments.Create(ctx, scope, name, params, nil)
		if err == nil {
			return nil
		}

		switch armErrorCode(err) {
		case "RoleAssignmentExists":
			return nil

		case "PrincipalNotFound", "PrincipalTypeNotSupported":
			if az.now().After(deadline) {
				return fmt.Errorf("service principal %s did not propagate within %s: %w", principalID, spPropagationTimeout, err)
			}
			if sleepErr := az.sleep(ctx, backoff); sleepErr != nil {
				return sleepErr
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}

		default:
			return Classify(err, Operation{Provider: "Microsoft.Authorization", RoleAssignment: true, Scope: scope})
		}
	}
}

// deleteRoleAssignments removes every grant this package could have created
// for the principal, for the roles in roleIDs, at the subscription scope.
// Grants for other roles, or at other scopes, are left alone.
func (az *Azure) deleteRoleAssignments(ctx context.Context, principalID string) error {
	pager := az.roleAssignments.NewListForScopePager(az.scope(),
		&armauthorization.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", principalID)),
		})

	wantRoles := make(map[string]struct{}, len(roleIDs))
	for _, roleID := range roleIDs {
		wantRoles[strings.ToLower(az.roleDefinitionID(roleID))] = struct{}{}
	}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, ra := range page.Value {
			if ra == nil || ra.ID == nil || ra.Properties == nil {
				continue
			}
			if _, ours := wantRoles[strings.ToLower(deref(ra.Properties.RoleDefinitionID))]; !ours {
				continue
			}
			if _, err := az.roleAssignments.DeleteByID(ctx, *ra.ID, nil); err != nil {
				if armErrorCode(err) == "RoleAssignmentNotFound" || armStatusCode(err) == 404 {
					continue
				}
				return err
			}
		}
	}
	return nil
}

// assignmentName deterministically names a role assignment from the tuple
// that identifies it, so repeated Create calls for the same grant always
// address the same ARM object.
func assignmentName(scope, principalID, roleDefinitionID string) string {
	seed := strings.Join([]string{scope, principalID, roleDefinitionID}, "|")
	return uuid.NewSHA1(roleAssignmentNamespace, []byte(seed)).String()
}
