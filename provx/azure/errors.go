package azure

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// LocationMismatchError: a resource group of the requested name already
// exists in a different location. A resource group's location is immutable,
// so there is no way to converge it: renaming the request or moving the
// group are both outside what this package will do on its own.
type LocationMismatchError struct {
	ResourceGroup, Existing, Requested string
}

func (e *LocationMismatchError) Error() string {
	return fmt.Sprintf("resource group %s exists in %s, not the requested %s; a resource group's location cannot be changed",
		e.ResourceGroup, e.Existing, e.Requested)
}

// TenantMismatchError: the subscription's actual Entra tenant, read from
// ARM, differs from the one pinned at construction. Proceeding under the
// pinned value would register the federated credential's trust with the
// wrong tenant, so this is reported rather than silently preferred.
type TenantMismatchError struct {
	Pinned, Actual string
}

func (e *TenantMismatchError) Error() string {
	return fmt.Sprintf("subscription belongs to tenant %s, not the pinned %s", e.Actual, e.Pinned)
}

// IdentityNotOursError: the managed identity carries a federated credential
// this package does not recognize as its own - either a second credential
// alongside a matching one, or a single credential whose issuer, subject or
// audience differ. Either way the identity is not safely ours to use: a
// federated credential grants near-owner access to whoever can present a
// matching token, so adopting it on a name match alone would hand that
// access to something we did not create and cannot account for.
type IdentityNotOursError struct {
	Name, Reason string
}

func (e *IdentityNotOursError) Error() string {
	return fmt.Sprintf("managed identity carries a federated credential %q we do not recognize (%s); remove it before formae can adopt this identity",
		e.Name, e.Reason)
}

// RoleAssignmentForbiddenError: the caller cannot create role assignments at
// Scope. This is the normal-day failure for a subscription Contributor,
// whose notActions exclude Microsoft.Authorization/*/Write - Contributor is
// not enough, on purpose, to grant itself more.
type RoleAssignmentForbiddenError struct {
	Scope string
	Cause error
}

func (e *RoleAssignmentForbiddenError) Error() string {
	return fmt.Sprintf("cannot create role assignments at %s; this requires the Owner or User Access Administrator role", e.Scope)
}

func (e *RoleAssignmentForbiddenError) Unwrap() error { return e.Cause }

// ProviderNotRegisteredError: the subscription has never registered the
// resource provider a call depends on. Common on a fresh subscription.
// formae never registers a provider on the caller's behalf: that is a
// mutation nobody asked for.
type ProviderNotRegisteredError struct {
	Provider string
	Cause    error
}

func (e *ProviderNotRegisteredError) Error() string {
	return fmt.Sprintf("the %s resource provider is not registered on this subscription; register it and re-run", e.Provider)
}

func (e *ProviderNotRegisteredError) Unwrap() error { return e.Cause }

// PermissionDeniedError: the credentials reached ARM and were refused, on a
// call that is not a role assignment. Kept distinct from
// RoleAssignmentForbiddenError because both arrive as the same ARM error
// code (AuthorizationFailed) and the remedies are unrelated: one needs
// Owner/User Access Administrator specifically, the other needs whatever
// permission the failed action requires - which this package does not
// itself know, so it is left to the underlying ARM error Cause carries
// rather than guessed at.
type PermissionDeniedError struct {
	Cause error
}

func (e *PermissionDeniedError) Error() string {
	return fmt.Sprintf("permission denied: %v", e.Cause)
}

func (e *PermissionDeniedError) Unwrap() error { return e.Cause }

// Operation names the ARM call Classify is interpreting. The same error code
// means different things on different calls - most importantly,
// AuthorizationFailed means "you cannot assign roles" on a role assignment
// and "you cannot do this at all" on everything else - so Classify needs to
// know which call failed, not just how.
type Operation struct {
	// Provider is the resource provider this call depends on, named in
	// ProviderNotRegisteredError when the subscription has not registered it.
	Provider string

	// RoleAssignment is true only for the role assignment Create call, the
	// one operation where AuthorizationFailed has a distinct, actionable
	// meaning worth its own error type.
	RoleAssignment bool

	// Scope is the ARM scope a role assignment call was made at. Ignored
	// for every other operation.
	Scope string
}

// The resource providers this package's non-role-assignment calls depend on
// (role assignments carry their own Microsoft.Authorization Operation, built
// per call with its Scope). Resource group and subscription calls share one
// value: both are Microsoft.Resources, and there is nothing operation-
// specific to say about either beyond that.
var (
	opMicrosoftResources = Operation{Provider: "Microsoft.Resources"}
	opManagedIdentity    = Operation{Provider: "Microsoft.ManagedIdentity"}
)

// Classify maps an ARM failure onto one of the typed errors above, leaving
// anything it does not recognise as a generic error that carries the HTTP
// status and nothing else: the caller gets a status code to report, not a
// false claim that the failure is one of the known shapes.
func Classify(err error, op Operation) error {
	if err == nil {
		return nil
	}
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return err
	}

	switch respErr.ErrorCode {
	case "MissingSubscriptionRegistration":
		return &ProviderNotRegisteredError{Provider: op.Provider, Cause: err}

	case "AuthorizationFailed":
		if op.RoleAssignment {
			return &RoleAssignmentForbiddenError{Scope: op.Scope, Cause: err}
		}
		return &PermissionDeniedError{Cause: err}

	case "RoleAssignmentUpdateNotPermitted":
		if op.RoleAssignment {
			return &RoleAssignmentForbiddenError{Scope: op.Scope, Cause: err}
		}
	}

	// RoleAssignmentExists and PrincipalNotFound/PrincipalTypeNotSupported
	// have no case here: ensureRoleAssignment's own retry loop (roles.go)
	// intercepts all three before any of them reach Classify, so a case for
	// them here would be dead code with no caller.

	// Empty or unrecognised: a generic error carrying the status, and
	// deliberately no cause - the raw ARM error is not exposed as something
	// callers can errors.Is/errors.As their way back to, since nothing here
	// classified it into a shape worth matching on.
	return fmt.Errorf("azure request failed with status %d", respErr.StatusCode)
}
