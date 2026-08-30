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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
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

	ownerTagKey   = "formae:owned"
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
// azTenantID is the subscription's Entra tenant. formaeTenantID is the
// formae tenant whose installation this is, and it appears in the federated
// credential's subject; the two are unrelated and never spelled alike. The
// ambient credential needs subscription-scoped Microsoft.ManagedIdentity
// write access to provision the identity, and Owner or User Access
// Administrator to create role assignments.
func New(logger *slog.Logger, subscriptionID, azTenantID, formaeTenantID, installationID, resourceGroup, location string) (*Azure, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var missing []string
	for _, arg := range []struct{ name, value string }{
		{"subscriptionID", subscriptionID},
		{"azTenantID", azTenantID},
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
	subClient, err := armsubscription.NewSubscriptionsClient(cred, nil)
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
