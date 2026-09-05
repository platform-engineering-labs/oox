package azure

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/google/uuid"
	"github.com/platform-engineering-labs/oox/provx"
)

const (
	// identityPrefix names the user-assigned identity deterministically per
	// installation, so Create and Delete always agree on which object is
	// this installation's without persisting an id anywhere.
	identityPrefix = "formae-ai-"

	// credentialName is the federated identity credential's resource name.
	credentialName = "formae-ai"

	ownerTagKey   = "formae-owned"
	ownerTagValue = "true"

	// Built-in Azure role definition ids. These GUIDs are stable across
	// every Azure cloud and tenant.
	contributorRoleID     = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	userAccessAdminRoleID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
)

// roleAssignmentNamespace seeds the deterministic UUID used as the role
// assignment resource name, so repeated Create calls address the same object.
var roleAssignmentNamespace = uuid.MustParse("2b8f5a1c-3e4d-4a6b-9c0e-7f1d2a3b4c5d")

// Azure provisions the formae-ai connection resources for one installation in
// a single subscription.
type Azure struct {
	logger *slog.Logger

	subscriptionID string
	azTenantID     string
	formaeTenantID string
	installationID string
	resourceGroup  string
	location       string

	// issuer and subject are derived once at construction: the issuer never
	// varies, and the subject is a pure function of the two tenant ids.
	issuer  string
	subject string

	resourceGroups  resourceGroupsAPI
	identities      userAssignedIdentitiesAPI
	federatedCreds  federatedIdentityCredentialsAPI
	roleAssignments roleAssignmentsAPI
	subscriptions   subscriptionsAPI

	// now and sleep are the clock the service-principal-propagation retry
	// loop reads, so tests can drive it through a full timeout without
	// actually waiting on one.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// New builds an Azure provisioner backed by the ambient credential (env
// vars, workload identity, managed identity, or `az login`).
//
// azTenantID is the subscription's Entra tenant, and it is optional: derivation
// from the subscription itself is the normal path (VerifySubscription reads it
// straight from ARM), but an external or guest account sometimes needs an
// explicit tenant in order to authenticate at all, before the subscription can
// even be reached. Pass "" to derive; pass a tenant to have it cross-checked
// against what the subscription actually reports, with disagreement reported
// as *TenantMismatchError rather than silently preferred either way.
//
// formaeTenantID is the formae tenant whose installation this is, and it
// appears in the federated credential's subject; the two are unrelated and
// never spelled alike. The ambient credential needs subscription-scoped
// Microsoft.ManagedIdentity write access to provision the identity, and Owner
// or User Access Administrator to create role assignments.
func New(logger *slog.Logger, subscriptionID, azTenantID, formaeTenantID, installationID, resourceGroup, location string) (*Azure, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var missing []string
	for _, arg := range []struct{ name, value string }{
		{"subscriptionID", subscriptionID},
		// azTenantID is deliberately not required: "" means derive it from
		// the subscription.
		{"formaeTenantID", formaeTenantID},
		{"installationID", installationID},
		{"resourceGroup", resourceGroup},
		{"location", location},
	} {
		if arg.value == "" {
			missing = append(missing, arg.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("azure: missing required argument(s): %s", strings.Join(missing, ", "))
	}

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		TenantID: azTenantID,
	})
	if err != nil {
		return nil, fmt.Errorf("azure: building credential: %w", err)
	}

	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building resource groups client: %w", err)
	}
	idClient, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building managed identities client: %w", err)
	}
	fedClient, err := armmsi.NewFederatedIdentityCredentialsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building federated credentials client: %w", err)
	}
	authFactory, err := armauthorization.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building authorization client: %w", err)
	}
	subClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building subscriptions client: %w", err)
	}

	return newWithClients(logger, subscriptionID, azTenantID, formaeTenantID, installationID, resourceGroup, location,
		rgClient, idClient, fedClient, authFactory.NewRoleAssignmentsClient(), subClient), nil
}

// newWithClients builds an Azure provisioner from already-constructed
// clients, so tests can substitute fakes without a network or a credential.
func newWithClients(logger *slog.Logger, subscriptionID, azTenantID, formaeTenantID, installationID, resourceGroup, location string,
	rg resourceGroupsAPI, ids userAssignedIdentitiesAPI, fed federatedIdentityCredentialsAPI, roles roleAssignmentsAPI, subs subscriptionsAPI) *Azure {
	return &Azure{
		logger:          logger,
		subscriptionID:  subscriptionID,
		azTenantID:      azTenantID,
		formaeTenantID:  formaeTenantID,
		installationID:  installationID,
		resourceGroup:   resourceGroup,
		location:        location,
		issuer:          "https://" + provx.Endpoint,
		subject:         provx.Subject(formaeTenantID, installationID),
		resourceGroups:  rg,
		identities:      ids,
		federatedCreds:  fed,
		roleAssignments: roles,
		subscriptions:   subs,
		now:             time.Now,
		sleep:           sleepContext,
	}
}

// sleepContext is the real clock's sleep: it waits out d, or returns early
// with ctx's error if ctx is cancelled first.
func sleepContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Result reports the coordinates Create converged to.
type Result struct {
	// TenantID is the subscription's Entra tenant, registered as
	// azureTenantId.
	TenantID string
	// ClientID is the managed identity's client id (its "appId"), registered
	// as azureClientId. This is distinct from PrincipalID, its service
	// principal object id: confusing the two is a real and easy failure.
	ClientID      string
	PrincipalID   string
	IdentityID    string
	ResourceGroup string
	Location      string
}

// Create converges every resource this connection needs: the resource
// group, the managed identity, its federated identity credential, and the
// subscription-scoped role assignments. Each step is independently
// idempotent, and existing objects are adopted under the ownership rules
// ensureIdentity and ensureFederatedCredential enforce, so re-running
// Create converges rather than duplicating anything.
func (az *Azure) Create(ctx context.Context) (*Result, error) {
	tenantID, err := az.VerifySubscription(ctx)
	if err != nil {
		return nil, err
	}

	if err := az.ensureResourceGroup(ctx); err != nil {
		return nil, err
	}

	identity, err := az.ensureIdentity(ctx)
	if err != nil {
		return nil, err
	}

	if err := az.ensureFederatedCredential(ctx); err != nil {
		return nil, err
	}

	var clientID, principalID string
	if identity.Properties != nil {
		clientID = deref(identity.Properties.ClientID)
		principalID = deref(identity.Properties.PrincipalID)
	}

	if err := az.ensureRoleAssignments(ctx, principalID); err != nil {
		return nil, err
	}

	az.logger.Info("azure connect resources ready",
		"clientId", clientID, "principalId", principalID, "identityId", deref(identity.ID))

	return &Result{
		TenantID:      tenantID,
		ClientID:      clientID,
		PrincipalID:   principalID,
		IdentityID:    deref(identity.ID),
		ResourceGroup: az.resourceGroup,
		Location:      az.location,
	}, nil
}

// Delete removes this installation's role assignments and managed identity.
// It never removes the resource group, which may hold other installations'
// identities, and it revalidates the identity's federated credential before
// deleting anything: resolving by the deterministic name alone and deleting
// whatever sits there would destroy a foreign identity that happens to
// occupy it. A missing identity is treated as already deleted.
func (az *Azure) Delete(ctx context.Context) error {
	existing, err := az.identities.Get(ctx, az.resourceGroup, az.identityName(), nil)
	if err != nil {
		if armStatusCode(err) == 404 {
			return nil
		}
		return Classify(err, opManagedIdentity)
	}

	if err := az.verifyFederatedCredential(ctx); err != nil {
		return err
	}

	var principalID string
	if existing.Properties != nil {
		principalID = deref(existing.Properties.PrincipalID)
	}
	if principalID != "" {
		if err := az.deleteRoleAssignments(ctx, principalID); err != nil {
			return err
		}
	}

	if _, err := az.identities.Delete(ctx, az.resourceGroup, az.identityName(), nil); err != nil && armStatusCode(err) != 404 {
		return Classify(err, opManagedIdentity)
	}
	return nil
}

// VerifySubscription confirms the ambient credential can reach the target
// subscription and returns its actual Entra tenant, read from ARM rather
// than trusted from the caller: Microsoft.Resources' Subscriptions.Get
// response carries a TenantID field precisely so this doesn't have to be
// taken on faith. When azTenantID was already pinned at construction, the
// two are cross-checked - continuing under a mismatched tenant would
// register a federated credential trust with the wrong one - and a
// disagreement is reported as *TenantMismatchError rather than silently
// preferring one value over the other.
func (az *Azure) VerifySubscription(ctx context.Context) (string, error) {
	resp, err := az.subscriptions.Get(ctx, az.subscriptionID, nil)
	if err != nil {
		return "", Classify(err, opMicrosoftResources)
	}

	actual := deref(resp.TenantID)
	if actual == "" {
		// ARM did not report one. Fall back to what the caller pinned
		// rather than returning an empty tenant.
		return az.azTenantID, nil
	}
	if az.azTenantID != "" && actual != az.azTenantID {
		return "", &TenantMismatchError{Pinned: az.azTenantID, Actual: actual}
	}
	return actual, nil
}

// identityName is the deterministic name of this installation's managed
// identity.
func (az *Azure) identityName() string {
	return identityPrefix + az.installationID
}

// scope is the ARM scope the role assignments are applied at.
func (az *Azure) scope() string {
	return "/subscriptions/" + az.subscriptionID
}

func (az *Azure) roleDefinitionID(roleID string) string {
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		az.subscriptionID, roleID)
}

// deref returns the string a pointer refers to, or "" for nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sameStrings reports whether have and want contain the same set of strings,
// ignoring order.
func sameStrings(have, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	seen := make(map[string]struct{}, len(want))
	for _, w := range want {
		seen[w] = struct{}{}
	}
	for _, h := range have {
		if _, ok := seen[h]; !ok {
			return false
		}
	}
	return true
}

func armErrorCode(err error) string {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.ErrorCode
	}
	return ""
}

func armStatusCode(err error) int {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode
	}
	return 0
}
