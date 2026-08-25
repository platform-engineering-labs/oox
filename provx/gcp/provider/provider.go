// Package provider provides idempotent helpers for managing Google Cloud
// Workload Identity Federation resources: pools, OIDC providers, and the IAM
// policy bindings that grant federated principals access to resources.
//
// Every Ensure*/Delete* function in this package is safe to call repeatedly.
// Re-running a create is a no-op (or a converging update); re-running a delete
// against a missing or already-deleted resource returns nil.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

const (
	defaultLocation = "global"

	stateActive  = "ACTIVE"
	stateDeleted = "DELETED"
)

// Client wraps the IAM and Cloud Resource Manager services.
type Client struct {
	iam *iam.Service
	crm *cloudresourcemanager.Service

	// PollInterval is how often long-running operations are polled.
	PollInterval time.Duration
	// PollTimeout bounds how long we wait for a single operation.
	PollTimeout time.Duration
}

// NewClient builds a Client using Application Default Credentials unless
// overridden via opts.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	iamSvc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("iam.NewService: %w", err)
	}
	crmSvc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager.NewService: %w", err)
	}
	return &Client{
		iam:          iamSvc,
		crm:          crmSvc,
		PollInterval: 2 * time.Second,
		PollTimeout:  5 * time.Minute,
	}, nil
}

// -----------------------------------------------------------------------------
// Specs
// -----------------------------------------------------------------------------

// PoolSpec identifies and describes a workload identity pool.
type PoolSpec struct {
	// Project is the project ID or project number that owns the pool.
	Project string
	// Location defaults to "global".
	Location string
	// PoolID is the user-chosen ID, 4-32 chars, must not start with "gcp-".
	PoolID string

	DisplayName string
	Description string
	Disabled    bool
}

func (p PoolSpec) location() string {
	if p.Location == "" {
		return defaultLocation
	}
	return p.Location
}

// Parent returns "projects/{project}/locations/{location}".
func (p PoolSpec) Parent() string {
	return fmt.Sprintf("projects/%s/locations/%s", p.Project, p.location())
}

// Name returns the fully qualified pool resource name.
func (p PoolSpec) Name() string {
	return fmt.Sprintf("%s/workloadIdentityPools/%s", p.Parent(), p.PoolID)
}

func (p PoolSpec) validate() error {
	if p.Project == "" {
		return errors.New("wif: PoolSpec.Project is required")
	}
	if p.PoolID == "" {
		return errors.New("wif: PoolSpec.PoolID is required")
	}
	if strings.HasPrefix(p.PoolID, "gcp-") {
		return fmt.Errorf("wif: PoolID %q uses the reserved %q prefix", p.PoolID, "gcp-")
	}
	return nil
}

// OIDCProviderSpec describes an OIDC provider inside a pool.
type OIDCProviderSpec struct {
	ProviderID  string
	DisplayName string
	Description string

	// IssuerURI is the OIDC issuer, e.g. "https://token.actions.githubusercontent.com".
	IssuerURI string
	// AllowedAudiences may be empty, in which case the default audience
	// (the provider's full resource name URL) is used.
	AllowedAudiences []string
	// JWKSJSON optionally pins the signing keys instead of fetching the
	// issuer's well-known JWKS endpoint.
	JWKSJSON string

	// AttributeMapping must contain at least "google.subject".
	AttributeMapping map[string]string
	// AttributeCondition is an optional CEL expression, e.g.
	//   assertion.repository_owner == "my-org"
	AttributeCondition string

	Disabled bool
}

func (s OIDCProviderSpec) validate() error {
	if s.ProviderID == "" {
		return errors.New("wif: OIDCProviderSpec.ProviderID is required")
	}
	if s.IssuerURI == "" {
		return errors.New("wif: OIDCProviderSpec.IssuerURI is required")
	}
	if _, ok := s.AttributeMapping["google.subject"]; !ok {
		return errors.New(`wif: AttributeMapping must contain "google.subject"`)
	}
	return nil
}

func (s OIDCProviderSpec) name(pool PoolSpec) string {
	return fmt.Sprintf("%s/providers/%s", pool.Name(), s.ProviderID)
}

func (s OIDCProviderSpec) toAPI() *iam.WorkloadIdentityPoolProvider {
	return &iam.WorkloadIdentityPoolProvider{
		DisplayName:        s.DisplayName,
		Description:        s.Description,
		Disabled:           s.Disabled,
		AttributeMapping:   s.AttributeMapping,
		AttributeCondition: s.AttributeCondition,
		Oidc: &iam.Oidc{
			IssuerUri:        s.IssuerURI,
			AllowedAudiences: s.AllowedAudiences,
			JwksJson:         s.JWKSJSON,
		},
		// Send Disabled even when false so it can be flipped back on update.
		ForceSendFields: []string{"Disabled"},
	}
}

// -----------------------------------------------------------------------------
// Pools
// -----------------------------------------------------------------------------

// EnsurePool creates the pool if it does not exist, undeletes it if it is in
// the soft-deleted state, and otherwise returns the existing pool. It is safe
// to call repeatedly.
func (c *Client) EnsurePool(ctx context.Context, spec PoolSpec) (*iam.WorkloadIdentityPool, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}

	existing, err := c.getPool(ctx, spec.Name())
	if err != nil {
		return nil, err
	}

	switch {
	case existing == nil:
		// Not there: fall through and create it.

	case existing.State == stateDeleted:
		// Soft-deleted pools linger for ~30 days and their IDs cannot be
		// reused, so the only way to converge is to undelete.
		op, err := c.iam.Projects.Locations.WorkloadIdentityPools.
			Undelete(spec.Name(), &iam.UndeleteWorkloadIdentityPoolRequest{}).
			Context(ctx).Do()
		if err != nil {
			// A concurrent undelete already won the race.
			if !isConflict(err) {
				return nil, fmt.Errorf("undelete pool %q: %w", spec.Name(), err)
			}
		} else if err := c.waitOperation(ctx, op); err != nil {
			return nil, fmt.Errorf("undelete pool %q: %w", spec.Name(), err)
		}
		return c.mustGetPool(ctx, spec.Name())

	default:
		return existing, nil
	}

	pool := &iam.WorkloadIdentityPool{
		DisplayName:     spec.DisplayName,
		Description:     spec.Description,
		Disabled:        spec.Disabled,
		ForceSendFields: []string{"Disabled"},
	}

	op, err := c.iam.Projects.Locations.WorkloadIdentityPools.
		Create(spec.Parent(), pool).
		WorkloadIdentityPoolId(spec.PoolID).
		Context(ctx).Do()
	if err != nil {
		// Lost a race with another caller; that is still success for us.
		if isConflict(err) {
			return c.mustGetPool(ctx, spec.Name())
		}
		return nil, fmt.Errorf("create pool %q: %w", spec.Name(), err)
	}
	if err := c.waitOperation(ctx, op); err != nil {
		return nil, fmt.Errorf("create pool %q: %w", spec.Name(), err)
	}
	return c.mustGetPool(ctx, spec.Name())
}

// DeletePool deletes the pool. Missing or already-deleted pools are treated as
// success, so this is safe to call repeatedly.
//
// Note that deletion is soft: the pool stays in state DELETED for ~30 days,
// during which its ID cannot be reused (EnsurePool will undelete it instead).
func (c *Client) DeletePool(ctx context.Context, spec PoolSpec) error {
	if err := spec.validate(); err != nil {
		return err
	}

	existing, err := c.getPool(ctx, spec.Name())
	if err != nil {
		return err
	}
	if existing == nil || existing.State == stateDeleted {
		return nil
	}

	op, err := c.iam.Projects.Locations.WorkloadIdentityPools.
		Delete(spec.Name()).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete pool %q: %w", spec.Name(), err)
	}
	if err := c.waitOperation(ctx, op); err != nil {
		return fmt.Errorf("delete pool %q: %w", spec.Name(), err)
	}
	return nil
}

func (c *Client) getPool(ctx context.Context, name string) (*iam.WorkloadIdentityPool, error) {
	pool, err := c.iam.Projects.Locations.WorkloadIdentityPools.Get(name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get pool %q: %w", name, err)
	}
	return pool, nil
}

func (c *Client) mustGetPool(ctx context.Context, name string) (*iam.WorkloadIdentityPool, error) {
	pool, err := c.getPool(ctx, name)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, fmt.Errorf("pool %q not found after create/undelete", name)
	}
	return pool, nil
}

// -----------------------------------------------------------------------------
// Providers
// -----------------------------------------------------------------------------

// EnsureOIDCProvider creates the provider if absent, undeletes it if it is
// soft-deleted, and patches it if the live configuration has drifted from the
// spec. Safe to call repeatedly.
func (c *Client) EnsureOIDCProvider(ctx context.Context, pool PoolSpec, spec OIDCProviderSpec) (*iam.WorkloadIdentityPoolProvider, error) {
	if err := pool.validate(); err != nil {
		return nil, err
	}
	if err := spec.validate(); err != nil {
		return nil, err
	}

	name := spec.name(pool)

	existing, err := c.getProvider(ctx, name)
	if err != nil {
		return nil, err
	}

	if existing != nil && existing.State == stateDeleted {
		op, err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.
			Undelete(name, &iam.UndeleteWorkloadIdentityPoolProviderRequest{}).
			Context(ctx).Do()
		if err != nil {
			if !isConflict(err) {
				return nil, fmt.Errorf("undelete provider %q: %w", name, err)
			}
		} else if err := c.waitOperation(ctx, op); err != nil {
			return nil, fmt.Errorf("undelete provider %q: %w", name, err)
		}
		if existing, err = c.getProvider(ctx, name); err != nil {
			return nil, err
		}
	}

	if existing != nil {
		if !providerDrifted(existing, spec) {
			return existing, nil
		}
		op, err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.
			Patch(name, spec.toAPI()).
			UpdateMask("displayName,description,disabled,attributeMapping,attributeCondition,oidc").
			Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("update provider %q: %w", name, err)
		}
		if err := c.waitOperation(ctx, op); err != nil {
			return nil, fmt.Errorf("update provider %q: %w", name, err)
		}
		return c.mustGetProvider(ctx, name)
	}

	op, err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.
		Create(pool.Name(), spec.toAPI()).
		WorkloadIdentityPoolProviderId(spec.ProviderID).
		Context(ctx).Do()
	if err != nil {
		if isConflict(err) {
			return c.mustGetProvider(ctx, name)
		}
		return nil, fmt.Errorf("create provider %q: %w", name, err)
	}
	if err := c.waitOperation(ctx, op); err != nil {
		return nil, fmt.Errorf("create provider %q: %w", name, err)
	}
	return c.mustGetProvider(ctx, name)
}

// DeleteOIDCProvider deletes a provider. Missing or already-deleted providers
// are treated as success.
func (c *Client) DeleteOIDCProvider(ctx context.Context, pool PoolSpec, providerID string) error {
	if err := pool.validate(); err != nil {
		return err
	}
	name := fmt.Sprintf("%s/providers/%s", pool.Name(), providerID)

	existing, err := c.getProvider(ctx, name)
	if err != nil {
		return err
	}
	if existing == nil || existing.State == stateDeleted {
		return nil
	}

	op, err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.
		Delete(name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete provider %q: %w", name, err)
	}
	if err := c.waitOperation(ctx, op); err != nil {
		return fmt.Errorf("delete provider %q: %w", name, err)
	}
	return nil
}

// GetOIDCProvider returns the provider if it exists, or nil if it does not.
//
// Exported because a caller that shares one provider across several tenants
// has to decide whether the object it found is actually its own before
// EnsureOIDCProvider patches it: the Ensure call converges whatever it finds at
// that name, which on a name collision would rewrite somebody else's trust.
func (c *Client) GetOIDCProvider(ctx context.Context, pool PoolSpec, providerID string) (*iam.WorkloadIdentityPoolProvider, error) {
	if err := pool.validate(); err != nil {
		return nil, err
	}
	return c.getProvider(ctx, fmt.Sprintf("%s/providers/%s", pool.Name(), providerID))
}

func (c *Client) getProvider(ctx context.Context, name string) (*iam.WorkloadIdentityPoolProvider, error) {
	p, err := c.iam.Projects.Locations.WorkloadIdentityPools.Providers.Get(name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get provider %q: %w", name, err)
	}
	return p, nil
}

func (c *Client) mustGetProvider(ctx context.Context, name string) (*iam.WorkloadIdentityPoolProvider, error) {
	p, err := c.getProvider(ctx, name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("provider %q not found after create/undelete", name)
	}
	return p, nil
}

func providerDrifted(got *iam.WorkloadIdentityPoolProvider, want OIDCProviderSpec) bool {
	if got.DisplayName != want.DisplayName ||
		got.Description != want.Description ||
		got.Disabled != want.Disabled ||
		got.AttributeCondition != want.AttributeCondition {
		return true
	}
	if !reflect.DeepEqual(nonEmptyMap(got.AttributeMapping), nonEmptyMap(want.AttributeMapping)) {
		return true
	}
	if got.Oidc == nil {
		return true
	}
	if got.Oidc.IssuerUri != want.IssuerURI {
		return true
	}
	// Only compare when the caller pinned an explicit list. Observed against
	// the live API: a provider created without allowedAudiences comes back
	// with the field absent, not with a materialized default, so an empty
	// "want" cannot be compared against anything meaningful. Note the
	// consequence for a caller that starts pinning the field on a provider
	// that did not have it: that is a real narrowing, from GCP's implicit
	// default (which also accepts the https:// spelling of the resource name)
	// to exactly the listed audiences.
	if len(want.AllowedAudiences) > 0 &&
		!reflect.DeepEqual(got.Oidc.AllowedAudiences, want.AllowedAudiences) {
		return true
	}
	if want.JWKSJSON != "" && got.Oidc.JwksJson != want.JWKSJSON {
		return true
	}
	return false
}

func nonEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// -----------------------------------------------------------------------------
// Principals
// -----------------------------------------------------------------------------

// ProjectNumber resolves a project ID to its numeric ID. IAM member strings for
// workload identity pools must use the project *number*, not the project ID.
func (c *Client) ProjectNumber(ctx context.Context, project string) (string, error) {
	p, err := c.crm.Projects.Get("projects/" + project).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get project %q: %w", project, err)
	}
	return strings.TrimPrefix(p.Name, "projects/"), nil
}

// SubjectPrincipal returns the IAM member string for one federated subject:
//
//	principal://iam.googleapis.com/projects/{number}/locations/{loc}/workloadIdentityPools/{pool}/subject/{subject}
//
// projectNumber must be the numeric project ID.
func SubjectPrincipal(projectNumber, location, poolID, subject string) string {
	if location == "" {
		location = defaultLocation
	}
	return fmt.Sprintf(
		"principal://iam.googleapis.com/projects/%s/locations/%s/workloadIdentityPools/%s/subject/%s",
		projectNumber, location, poolID, subject,
	)
}

// AttributePrincipalSet returns the member string for every identity in the
// pool whose mapped attribute equals value, e.g. attribute "repository" and
// value "my-org/my-repo".
func AttributePrincipalSet(projectNumber, location, poolID, attribute, value string) string {
	if location == "" {
		location = defaultLocation
	}
	return fmt.Sprintf(
		"principalSet://iam.googleapis.com/projects/%s/locations/%s/workloadIdentityPools/%s/attribute.%s/%s",
		projectNumber, location, poolID, attribute, value,
	)
}

// PoolPrincipalSet returns the member string matching every identity in the pool.
func PoolPrincipalSet(projectNumber, location, poolID string) string {
	if location == "" {
		location = defaultLocation
	}
	return fmt.Sprintf(
		"principalSet://iam.googleapis.com/projects/%s/locations/%s/workloadIdentityPools/%s/*",
		projectNumber, location, poolID,
	)
}

// SubjectPrincipal builds the member string for a subject in this pool,
// resolving the project number automatically.
func (c *Client) SubjectPrincipal(ctx context.Context, pool PoolSpec, subject string) (string, error) {
	num, err := c.ProjectNumber(ctx, pool.Project)
	if err != nil {
		return "", err
	}
	return SubjectPrincipal(num, pool.location(), pool.PoolID, subject), nil
}

// -----------------------------------------------------------------------------
// IAM bindings
// -----------------------------------------------------------------------------

// Binding is a single (role, member, optional condition) tuple.
type Binding struct {
	Role   string
	Member string

	// ConditionTitle and ConditionExpression are optional. When set, the
	// binding is matched and written as a conditional binding, which requires
	// policy version 3.
	ConditionTitle       string
	ConditionExpression  string
	ConditionDescription string
}

func (b Binding) validate() error {
	if b.Role == "" {
		return errors.New("wif: Binding.Role is required")
	}
	if b.Member == "" {
		return errors.New("wif: Binding.Member is required")
	}
	if (b.ConditionExpression == "") != (b.ConditionTitle == "") {
		return errors.New("wif: ConditionTitle and ConditionExpression must be set together")
	}
	return nil
}

const maxPolicyAttempts = 5

// EnsureProjectBinding grants b.Role to b.Member on the project. If the binding
// already exists the policy is not rewritten at all, so this is both idempotent
// and cheap to re-run.
func (c *Client) EnsureProjectBinding(ctx context.Context, project string, b Binding) error {
	return c.mutateProjectPolicy(ctx, project, b, true)
}

// RemoveProjectBinding revokes b.Role from b.Member on the project. A binding
// that is already absent is a no-op.
func (c *Client) RemoveProjectBinding(ctx context.Context, project string, b Binding) error {
	return c.mutateProjectPolicy(ctx, project, b, false)
}

func (c *Client) mutateProjectPolicy(ctx context.Context, project string, b Binding, add bool) error {
	if err := b.validate(); err != nil {
		return err
	}
	resource := "projects/" + strings.TrimPrefix(project, "projects/")

	var lastErr error
	for attempt := 0; attempt < maxPolicyAttempts; attempt++ {
		policy, err := c.crm.Projects.GetIamPolicy(resource, &cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
		}).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("get IAM policy for %q: %w", resource, err)
		}

		changed := applyCRMBinding(policy, b, add)
		if !changed {
			return nil // already in the desired state
		}
		policy.Version = 3

		_, err = c.crm.Projects.SetIamPolicy(resource, &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}).Context(ctx).Do()
		if err == nil {
			return nil
		}
		if !isRetryablePolicyErr(err) {
			return fmt.Errorf("set IAM policy for %q: %w", resource, err)
		}
		lastErr = err
		sleepCtx(ctx, backoff(attempt))
	}
	return fmt.Errorf("set IAM policy for %q: exhausted retries: %w", resource, lastErr)
}

// EnsureServiceAccountBinding grants b.Role to b.Member on a service account.
// The common case is granting roles/iam.workloadIdentityUser to a federated
// principal so it can impersonate the service account.
//
// serviceAccount may be an email address or a full
// "projects/-/serviceAccounts/{email}" resource name.
func (c *Client) EnsureServiceAccountBinding(ctx context.Context, serviceAccount string, b Binding) error {
	return c.mutateServiceAccountPolicy(ctx, serviceAccount, b, true)
}

// RemoveServiceAccountBinding revokes b.Role from b.Member on a service account.
func (c *Client) RemoveServiceAccountBinding(ctx context.Context, serviceAccount string, b Binding) error {
	return c.mutateServiceAccountPolicy(ctx, serviceAccount, b, false)
}

func (c *Client) mutateServiceAccountPolicy(ctx context.Context, serviceAccount string, b Binding, add bool) error {
	if err := b.validate(); err != nil {
		return err
	}
	resource := serviceAccount
	if !strings.HasPrefix(resource, "projects/") {
		resource = "projects/-/serviceAccounts/" + resource
	}

	var lastErr error
	for attempt := 0; attempt < maxPolicyAttempts; attempt++ {
		policy, err := c.iam.Projects.ServiceAccounts.
			GetIamPolicy(resource).
			OptionsRequestedPolicyVersion(3).
			Context(ctx).Do()
		if err != nil {
			if isNotFound(err) && !add {
				return nil // nothing to revoke on a service account that is gone
			}
			return fmt.Errorf("get IAM policy for %q: %w", resource, err)
		}

		changed := applyIAMBinding(policy, b, add)
		if !changed {
			return nil
		}
		policy.Version = 3

		_, err = c.iam.Projects.ServiceAccounts.SetIamPolicy(resource, &iam.SetIamPolicyRequest{
			Policy: policy,
		}).Context(ctx).Do()
		if err == nil {
			return nil
		}
		if !isRetryablePolicyErr(err) {
			return fmt.Errorf("set IAM policy for %q: %w", resource, err)
		}
		lastErr = err
		sleepCtx(ctx, backoff(attempt))
	}
	return fmt.Errorf("set IAM policy for %q: exhausted retries: %w", resource, lastErr)
}

// applyCRMBinding mutates policy in place and reports whether anything changed.
func applyCRMBinding(policy *cloudresourcemanager.Policy, b Binding, add bool) bool {
	for i, existing := range policy.Bindings {
		if existing.Role != b.Role || !crmConditionMatches(existing.Condition, b) {
			continue
		}
		idx := indexOf(existing.Members, b.Member)
		if add {
			if idx >= 0 {
				return false
			}
			existing.Members = append(existing.Members, b.Member)
			return true
		}
		if idx < 0 {
			return false
		}
		existing.Members = append(existing.Members[:idx], existing.Members[idx+1:]...)
		if len(existing.Members) == 0 {
			policy.Bindings = append(policy.Bindings[:i], policy.Bindings[i+1:]...)
		}
		return true
	}

	if !add {
		return false
	}
	nb := &cloudresourcemanager.Binding{
		Role:    b.Role,
		Members: []string{b.Member},
	}
	if b.ConditionExpression != "" {
		nb.Condition = &cloudresourcemanager.Expr{
			Title:       b.ConditionTitle,
			Expression:  b.ConditionExpression,
			Description: b.ConditionDescription,
		}
	}
	policy.Bindings = append(policy.Bindings, nb)
	return true
}

// applyIAMBinding is the same logic against the iam/v1 policy types.
func applyIAMBinding(policy *iam.Policy, b Binding, add bool) bool {
	for i, existing := range policy.Bindings {
		if existing.Role != b.Role || !iamConditionMatches(existing.Condition, b) {
			continue
		}
		idx := indexOf(existing.Members, b.Member)
		if add {
			if idx >= 0 {
				return false
			}
			existing.Members = append(existing.Members, b.Member)
			return true
		}
		if idx < 0 {
			return false
		}
		existing.Members = append(existing.Members[:idx], existing.Members[idx+1:]...)
		if len(existing.Members) == 0 {
			policy.Bindings = append(policy.Bindings[:i], policy.Bindings[i+1:]...)
		}
		return true
	}

	if !add {
		return false
	}
	nb := &iam.Binding{
		Role:    b.Role,
		Members: []string{b.Member},
	}
	if b.ConditionExpression != "" {
		nb.Condition = &iam.Expr{
			Title:       b.ConditionTitle,
			Expression:  b.ConditionExpression,
			Description: b.ConditionDescription,
		}
	}
	policy.Bindings = append(policy.Bindings, nb)
	return true
}

func crmConditionMatches(c *cloudresourcemanager.Expr, b Binding) bool {
	if c == nil {
		return b.ConditionExpression == ""
	}
	return c.Expression == b.ConditionExpression && c.Title == b.ConditionTitle
}

func iamConditionMatches(c *iam.Expr, b Binding) bool {
	if c == nil {
		return b.ConditionExpression == ""
	}
	return c.Expression == b.ConditionExpression && c.Title == b.ConditionTitle
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// -----------------------------------------------------------------------------
// Operations & error helpers
// -----------------------------------------------------------------------------

func (c *Client) waitOperation(ctx context.Context, op *iam.Operation) error {
	if op == nil {
		return nil
	}
	if op.Done {
		return operationError(op)
	}

	interval := c.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	timeout := c.PollTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	deadline := time.Now().Add(timeout)
	name := op.Name

	for {
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}

		var (
			got *iam.Operation
			err error
		)
		if strings.Contains(name, "/providers/") {
			got, err = c.iam.Projects.Locations.WorkloadIdentityPools.Providers.Operations.
				Get(name).Context(ctx).Do()
		} else {
			got, err = c.iam.Projects.Locations.WorkloadIdentityPools.Operations.
				Get(name).Context(ctx).Do()
		}
		if err != nil {
			// A finished delete can make the operation unreadable; treat that
			// as completion rather than failure.
			if isNotFound(err) {
				return nil
			}
			return fmt.Errorf("poll operation %q: %w", name, err)
		}
		if got.Done {
			return operationError(got)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("operation %q did not complete within %s", name, timeout)
		}
	}
}

func operationError(op *iam.Operation) error {
	if op == nil || op.Error == nil {
		return nil
	}
	return fmt.Errorf("operation failed (code %d): %s", op.Error.Code, op.Error.Message)
}

func apiCode(err error) int {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		return gerr.Code
	}
	return 0
}

func isNotFound(err error) bool { return apiCode(err) == http.StatusNotFound }

// isConflict covers both ALREADY_EXISTS and ABORTED, which the JSON API both
// surface as HTTP 409.
func isConflict(err error) bool { return apiCode(err) == http.StatusConflict }

func isRetryablePolicyErr(err error) bool {
	switch apiCode(err) {
	case http.StatusConflict, http.StatusPreconditionFailed,
		http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusServiceUnavailable:
		return true
	}
	return false
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt)) * 250 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
