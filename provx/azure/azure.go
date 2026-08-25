package azure

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/google/uuid"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphapps "github.com/microsoftgraph/msgraph-sdk-go/applications"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	graphsps "github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/platform-engineering-labs/oox/provx"
)

const (
	// resourceName is the well-known display name used for both the app
	// registration and the federated identity credential.
	resourceName = "formae-ai"

	oidcIssuer    = "https://" + provx.Endpoint
	tokenAudience = "api://AzureADTokenExchange"

	// contributorRoleDefinitionID is the built-in Contributor role. This GUID
	// is stable across every Azure cloud and tenant.
	contributorRoleDefinitionID = "b24988ac-6180-42a0-ab88-20f7382dd24c"

	// spPropagationTimeout bounds how long we wait for a freshly created
	// service principal to become visible to ARM.
	spPropagationTimeout = 3 * time.Minute
)

// graphScope is the OAuth scope required for Microsoft Graph calls.
var graphScope = []string{"https://graph.microsoft.com/.default"}

// roleAssignmentNamespace seeds the deterministic UUID used as the role
// assignment resource name, so repeated Create calls address the same object.
var roleAssignmentNamespace = uuid.MustParse("2b8f5a1c-3e4d-4a6b-9c0e-7f1d2a3b4c5d")

// Azure manages the formae-ai identity resources in a single subscription.
type Azure struct {
	logger *slog.Logger

	subscriptionId string
	azTenantId     string

	tenantId       string
	installationId string

	graph           *msgraphsdk.GraphServiceClient
	roleAssignments *armauthorization.RoleAssignmentsClient
}

// New builds an Azure manager.
//
// The ambient credential (env vars, workload identity, managed identity, or
// `az login`) needs:
//   - Microsoft Graph: Application.ReadWrite.All, or the "Application
//     Administrator" directory role, to create and delete app registrations.
//   - ARM: Microsoft.Authorization/roleAssignments/write and /delete at the
//     subscription scope — "User Access Administrator" or "Owner".
func New(logger *slog.Logger, subscriptionId, azTenantId, tenantId, installationId string) (*Azure, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var missing []string
	if subscriptionId == "" {
		missing = append(missing, "subscriptionId")
	}
	if azTenantId == "" {
		missing = append(missing, "azTenantId")
	}
	if tenantId == "" {
		missing = append(missing, "tenantId")
	}
	if installationId == "" {
		missing = append(missing, "installationId")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("azure: missing required argument(s): %s", strings.Join(missing, ", "))
	}

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		TenantID: azTenantId,
	})
	if err != nil {
		return nil, fmt.Errorf("azure: building credential: %w", err)
	}

	graph, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, graphScope)
	if err != nil {
		return nil, fmt.Errorf("azure: building graph client: %w", err)
	}

	factory, err := armauthorization.NewClientFactory(subscriptionId, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: building authorization client: %w", err)
	}

	return &Azure{
		logger:          logger.With("component", "azure", "subscription", subscriptionId),
		subscriptionId:  subscriptionId,
		azTenantId:      azTenantId,
		tenantId:        tenantId,
		installationId:  installationId,
		graph:           graph,
		roleAssignments: factory.NewRoleAssignmentsClient(),
	}, nil
}

// scope is the ARM scope the Contributor grant is applied at.
func (az *Azure) scope() string {
	return "/subscriptions/" + az.subscriptionId
}

// roleDefinitionID is the fully qualified Contributor role definition.
func (az *Azure) roleDefinitionID() string {
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		az.subscriptionId, contributorRoleDefinitionID)
}

// subject is the "sub" claim Formae-issued tokens will carry.
func (az *Azure) subject() string {
	return fmt.Sprintf("fai:%s/%s", az.tenantId, az.installationId)
}

// Create provisions the app registration, service principal, federated
// identity credential, and Contributor role assignment. Existing objects are
// adopted and reconciled rather than duplicated.
func (az *Azure) Create(ctx context.Context) error {
	appObjectID, clientID, err := az.ensureApplication(ctx)
	if err != nil {
		return fmt.Errorf("azure: ensuring application %q: %w", resourceName, err)
	}

	spObjectID, err := az.ensureServicePrincipal(ctx, clientID)
	if err != nil {
		return fmt.Errorf("azure: ensuring service principal for appId %s: %w", clientID, err)
	}

	if err := az.ensureFederatedCredential(ctx, appObjectID); err != nil {
		return fmt.Errorf("azure: ensuring federated credential %q: %w", resourceName, err)
	}

	if err := az.ensureRoleAssignment(ctx, spObjectID); err != nil {
		return fmt.Errorf("azure: ensuring Contributor assignment at %s: %w", az.scope(), err)
	}

	az.logger.Info("azure connect resources ready",
		"clientId", clientID,
		"appObjectId", appObjectID,
		"servicePrincipalId", spObjectID)
	return nil
}

// Delete removes the role assignment, service principal, and app registration.
// Missing objects are treated as already deleted.
func (az *Azure) Delete(ctx context.Context) error {
	app, err := az.findApplication(ctx)
	if err != nil {
		return fmt.Errorf("azure: looking up application %q: %w", resourceName, err)
	}
	if app == nil {
		az.logger.Info("no application to delete", "displayName", resourceName)
		return nil
	}

	appObjectID := deref(app.GetId())
	clientID := deref(app.GetAppId())

	spObjectID, err := az.findServicePrincipal(ctx, clientID)
	if err != nil {
		return fmt.Errorf("azure: looking up service principal for appId %s: %w", clientID, err)
	}

	// Role assignments first — an orphaned assignment pointing at a deleted
	// principal is awkward to clean up afterwards.
	if spObjectID != "" {
		if err := az.deleteRoleAssignments(ctx, spObjectID); err != nil {
			return fmt.Errorf("azure: deleting role assignments for %s: %w", spObjectID, err)
		}

		if err := az.graph.ServicePrincipals().
			ByServicePrincipalId(spObjectID).
			Delete(ctx, nil); err != nil && !isGraphNotFound(err) {
			return fmt.Errorf("azure: deleting service principal %s: %w", spObjectID, graphErr(err))
		}
		az.logger.Info("deleted service principal", "servicePrincipalId", spObjectID)
	}

	// Deleting the application also removes its federated identity credentials.
	if err := az.graph.Applications().
		ByApplicationId(appObjectID).
		Delete(ctx, nil); err != nil && !isGraphNotFound(err) {
		return fmt.Errorf("azure: deleting application %s: %w", appObjectID, graphErr(err))
	}
	az.logger.Info("deleted application", "appObjectId", appObjectID, "clientId", clientID)

	return nil
}

// ---------------------------------------------------------------------------
// application registration
// ---------------------------------------------------------------------------

func (az *Azure) ensureApplication(ctx context.Context) (appObjectID, clientID string, err error) {
	existing, err := az.findApplication(ctx)
	if err != nil {
		return "", "", err
	}
	if existing != nil {
		az.logger.Debug("application already exists",
			"appObjectId", deref(existing.GetId()), "clientId", deref(existing.GetAppId()))
		return deref(existing.GetId()), deref(existing.GetAppId()), nil
	}

	body := graphmodels.NewApplication()
	body.SetDisplayName(to.Ptr(resourceName))
	body.SetSignInAudience(to.Ptr("AzureADMyOrg"))

	app, err := az.graph.Applications().Post(ctx, body, nil)
	if err != nil {
		return "", "", graphErr(err)
	}

	appObjectID, clientID = deref(app.GetId()), deref(app.GetAppId())
	if appObjectID == "" || clientID == "" {
		return "", "", errors.New("application response missing id or appId")
	}
	az.logger.Info("created application", "appObjectId", appObjectID, "clientId", clientID)
	return appObjectID, clientID, nil
}

func (az *Azure) findApplication(ctx context.Context) (graphmodels.Applicationable, error) {
	cfg := &graphapps.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &graphapps.ApplicationsRequestBuilderGetQueryParameters{
			Filter: to.Ptr(fmt.Sprintf("displayName eq '%s'", odataEscape(resourceName))),
			Select: []string{"id", "appId", "displayName"},
			Top:    to.Ptr(int32(2)),
		},
	}

	page, err := az.graph.Applications().Get(ctx, cfg)
	if err != nil {
		return nil, graphErr(err)
	}

	apps := page.GetValue()
	switch len(apps) {
	case 0:
		return nil, nil
	case 1:
		return apps[0], nil
	default:
		return nil, fmt.Errorf("found %d applications named %q; "+
			"refusing to guess which one to manage", len(apps), resourceName)
	}
}

// ---------------------------------------------------------------------------
// service principal
// ---------------------------------------------------------------------------

func (az *Azure) ensureServicePrincipal(ctx context.Context, clientID string) (string, error) {
	spObjectID, err := az.findServicePrincipal(ctx, clientID)
	if err != nil {
		return "", err
	}
	if spObjectID != "" {
		az.logger.Debug("service principal already exists", "servicePrincipalId", spObjectID)
		return spObjectID, nil
	}

	body := graphmodels.NewServicePrincipal()
	body.SetAppId(to.Ptr(clientID))

	sp, err := az.graph.ServicePrincipals().Post(ctx, body, nil)
	if err != nil {
		// A concurrent run may have won the race.
		if isGraphConflict(err) {
			if id, lookupErr := az.findServicePrincipal(ctx, clientID); lookupErr == nil && id != "" {
				return id, nil
			}
		}
		return "", graphErr(err)
	}

	spObjectID = deref(sp.GetId())
	if spObjectID == "" {
		return "", errors.New("service principal response missing id")
	}
	az.logger.Info("created service principal", "servicePrincipalId", spObjectID)
	return spObjectID, nil
}

func (az *Azure) findServicePrincipal(ctx context.Context, clientID string) (string, error) {
	if clientID == "" {
		return "", nil
	}

	cfg := &graphsps.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &graphsps.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: to.Ptr(fmt.Sprintf("appId eq '%s'", odataEscape(clientID))),
			Select: []string{"id", "appId"},
			Top:    to.Ptr(int32(1)),
		},
	}

	page, err := az.graph.ServicePrincipals().Get(ctx, cfg)
	if err != nil {
		return "", graphErr(err)
	}
	if sps := page.GetValue(); len(sps) > 0 {
		return deref(sps[0].GetId()), nil
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// federated identity credential
// ---------------------------------------------------------------------------

func (az *Azure) ensureFederatedCredential(ctx context.Context, appObjectID string) error {
	creds, err := az.graph.Applications().
		ByApplicationId(appObjectID).
		FederatedIdentityCredentials().
		Get(ctx, nil)
	if err != nil {
		return graphErr(err)
	}

	audiences := []string{tokenAudience}
	subject := az.subject()

	for _, existing := range creds.GetValue() {
		if deref(existing.GetName()) != resourceName {
			continue
		}

		// The name matches but issuer/subject/audiences are mutable, so
		// reconcile instead of leaving a stale credential in place. This is
		// what makes Create safe to re-run after an installationId change.
		if deref(existing.GetIssuer()) == oidcIssuer &&
			deref(existing.GetSubject()) == subject &&
			sameStrings(existing.GetAudiences(), audiences) {
			az.logger.Debug("federated credential already current", "name", resourceName)
			return nil
		}

		patch := graphmodels.NewFederatedIdentityCredential()
		patch.SetIssuer(to.Ptr(oidcIssuer))
		patch.SetSubject(to.Ptr(subject))
		patch.SetAudiences(audiences)

		if _, err := az.graph.Applications().
			ByApplicationId(appObjectID).
			FederatedIdentityCredentials().
			ByFederatedIdentityCredentialId(deref(existing.GetId())).
			Patch(ctx, patch, nil); err != nil {
			return graphErr(err)
		}
		az.logger.Info("updated federated credential", "name", resourceName, "subject", subject)
		return nil
	}

	body := graphmodels.NewFederatedIdentityCredential()
	body.SetName(to.Ptr(resourceName))
	body.SetIssuer(to.Ptr(oidcIssuer))
	body.SetSubject(to.Ptr(subject))
	body.SetAudiences(audiences)

	if _, err := az.graph.Applications().
		ByApplicationId(appObjectID).
		FederatedIdentityCredentials().
		Post(ctx, body, nil); err != nil {
		return graphErr(err)
	}
	az.logger.Info("created federated credential", "name", resourceName, "subject", subject)
	return nil
}

// ---------------------------------------------------------------------------
// role assignment
// ---------------------------------------------------------------------------

func (az *Azure) ensureRoleAssignment(ctx context.Context, spObjectID string) error {
	scope := az.scope()
	roleDefID := az.roleDefinitionID()

	// Deterministic name so re-runs address the same assignment resource.
	seed := strings.Join([]string{scope, spObjectID, roleDefID}, "|")
	name := uuid.NewSHA1(roleAssignmentNamespace, []byte(seed)).String()

	params := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			PrincipalID:      to.Ptr(spObjectID),
			RoleDefinitionID: to.Ptr(roleDefID),
			PrincipalType:    to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
		},
	}

	deadline := time.Now().Add(spPropagationTimeout)
	backoff := 2 * time.Second

	for {
		resp, err := az.roleAssignments.Create(ctx, scope, name, params, nil)
		if err == nil {
			az.logger.Info("created role assignment", "role", "Contributor", "id", deref(resp.ID))
			return nil
		}

		switch armErrorCode(err) {
		case "RoleAssignmentExists":
			az.logger.Debug("role assignment already exists", "role", "Contributor")
			return nil

		case "PrincipalNotFound", "PrincipalTypeNotSupported":
			// Entra ID replication lag: ARM cannot see the new SP yet.
			if time.Now().After(deadline) {
				return fmt.Errorf("service principal %s did not propagate within %s: %w",
					spObjectID, spPropagationTimeout, err)
			}
			az.logger.Debug("waiting for service principal to propagate", "backoff", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}

		default:
			return err
		}
	}
}

// deleteRoleAssignments removes every Contributor grant this package could have
// created for the principal at the subscription scope. Grants for other roles,
// or at other scopes, are left alone.
func (az *Azure) deleteRoleAssignments(ctx context.Context, spObjectID string) error {
	pager := az.roleAssignments.NewListForScopePager(az.scope(),
		&armauthorization.RoleAssignmentsClientListForScopeOptions{
			Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", spObjectID)),
		})

	wantRole := strings.ToLower(az.roleDefinitionID())

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, ra := range page.Value {
			if ra == nil || ra.ID == nil || ra.Properties == nil {
				continue
			}
			if !strings.EqualFold(deref(ra.Properties.RoleDefinitionID), wantRole) {
				continue
			}
			if _, err := az.roleAssignments.DeleteByID(ctx, *ra.ID, nil); err != nil {
				if armErrorCode(err) == "RoleAssignmentNotFound" || armStatusCode(err) == 404 {
					continue
				}
				return err
			}
			az.logger.Info("deleted role assignment", "id", *ra.ID)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

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

// odataEscape escapes single quotes for OData $filter string literals.
func odataEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// graphErr unwraps a Microsoft Graph ODataError, whose default Error() string
// is an unhelpful "error status code received from the API".
func graphErr(err error) error {
	var odErr *odataerrors.ODataError
	if !errors.As(err, &odErr) {
		return err
	}
	detail := odErr.GetErrorEscaped()
	if detail == nil {
		return err
	}
	return fmt.Errorf("graph %s: %s", deref(detail.GetCode()), deref(detail.GetMessage()))
}

func isGraphNotFound(err error) bool {
	var odErr *odataerrors.ODataError
	if errors.As(err, &odErr) {
		return odErr.ResponseStatusCode == 404
	}
	return false
}

func isGraphConflict(err error) bool {
	var odErr *odataerrors.ODataError
	if !errors.As(err, &odErr) {
		return false
	}
	if odErr.ResponseStatusCode == 409 {
		return true
	}
	if detail := odErr.GetErrorEscaped(); detail != nil {
		code := deref(detail.GetCode())
		return code == "Request_MultipleObjectsWithSameKeyValue" ||
			strings.Contains(code, "AlreadyExists")
	}
	return false
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
