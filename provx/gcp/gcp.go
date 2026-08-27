package gcp

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/api/option"

	"github.com/platform-engineering-labs/oox/provx"
	"github.com/platform-engineering-labs/oox/provx/gcp/provider"
)

const (
	// poolID and providerID are fixed per project rather than per
	// installation. One project can be connected to several installations -
	// the AWS path supports that deliberately - and a per-installation
	// provider would mean one federation object per installation for no gain,
	// since the object says nothing installation-specific.
	poolID     = "formae-ai"
	providerID = "formae-ai"

	// subjectNamespace is the prefix every subject this issuer mints carries.
	// The provider's attribute condition admits the namespace, not one
	// subject: which installations may actually reach the project is decided
	// by the IAM bindings below, and pinning the condition to a single subject
	// would mean the second installation to connect silently revoked the
	// first.
	subjectNamespace = "fai:"
)

// projectRoles is the connector's permission posture. It mirrors what
// formae-bootstrap grants a self-hosted agent for the same job: roles/editor
// is broad but excludes IAM policy management, and the projectIamAdmin binding
// adds exactly that back.
//
// Stated plainly, because "editor is not owner" invites the wrong impression:
// this is near-owner. A principal that can edit resources and rewrite project
// IAM can grant itself more. It is accepted because the agent's job is to
// manage arbitrary infrastructure in this project, including IAM.
var projectRoles = []string{
	"roles/editor",
	"roles/resourcemanager.projectIamAdmin",
}

type GCP struct {
	*slog.Logger

	client         *provider.Client
	project        string
	tenantId       string
	installationId string
	issuer         provx.Issuer
}

// New builds a provisioner for one installation's connection to one project.
//
// issuer is the outbound identity issuer the provider will trust, taken from
// the caller and validated here rather than compiled in. The AWS provisioner
// has always worked this way, and the reason is the same on both clouds: the
// issuer is produced by the control plane and travels verbatim into the trust
// artifacts, so a build that substituted its own would provision trust for an
// issuer the caller never named.
//
// The context is the caller's: it bounds the client construction, and the
// credential lookup that construction performs. opts are passed through to the
// underlying Google clients, which is how tests reach a fake without a network
// or a credential.
func New(ctx context.Context, logger *slog.Logger, project, tenantId, installationId, issuer string,
	opts ...option.ClientOption) (*GCP, error) {
	iss, err := provx.ParseIssuer(issuer)
	if err != nil {
		return nil, err
	}

	client, err := provider.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &GCP{
		Logger:         logger,
		client:         client,
		project:        project,
		tenantId:       tenantId,
		installationId: installationId,
		issuer:         iss,
	}, nil
}

// Result reports what Create converged to. ProviderName is the coordinate the
// connection is registered under and the audience of every token minted for
// it, so it is returned rather than reassembled by the caller.
type Result struct {
	ProviderName  string
	ProjectNumber string
	Member        string
	RolesGranted  []string
}

// VerifyProject resolves the project to its number, which doubles as the check
// that these credentials can actually reach the project the caller named.
//
// It distinguishes two failures the caller must not conflate: credentials that
// cannot be obtained at all (which a fresh login fixes) from a project that
// cannot be read with the credentials in hand (which it does not, and where
// re-authenticating would overwrite deliberately configured credentials while
// returning the same principal).
func (gcp *GCP) VerifyProject(ctx context.Context) (string, error) {
	number, err := gcp.client.ProjectNumber(ctx, gcp.project)
	if err != nil {
		if classified := classify(err); classified != err {
			return "", classified
		}
		return "", &ProjectUnreachableError{Project: gcp.project, Cause: err}
	}
	return number, nil
}

// Create converges the project to the state this installation needs: the
// shared pool, the shared OIDC provider trusting our issuer, and this
// installation's own IAM members.
//
// Every step is idempotent, and there is no rollback: the pool and provider
// may predate this call or be shared with another installation, so removing
// them on a partial failure would revoke somebody else. Re-running converges.
func (gcp *GCP) Create(ctx context.Context) (*Result, error) {
	number, err := gcp.VerifyProject(ctx)
	if err != nil {
		return nil, err
	}

	pool, oidc := gcp.spec(number)

	if _, err := gcp.client.EnsurePool(ctx, *pool); err != nil {
		return nil, classify(err)
	}

	if err := gcp.assertProviderIsOurs(ctx, *pool, number); err != nil {
		return nil, err
	}

	if _, err := gcp.client.EnsureOIDCProvider(ctx, *pool, *oidc); err != nil {
		return nil, classify(err)
	}

	member := principalFor(number, gcp.tenantId, gcp.installationId)
	for _, role := range projectRoles {
		binding := provider.Binding{Role: role, Member: member}
		if err := gcp.client.EnsureProjectBinding(ctx, gcp.project, binding); err != nil {
			return nil, classify(err)
		}
	}

	return &Result{
		ProviderName:  providerName(number),
		ProjectNumber: number,
		Member:        member,
		RolesGranted:  projectRoles,
	}, nil
}

// Delete revokes this installation's access and nothing else.
//
// It removes this installation's IAM members and leaves the pool and provider
// standing, because both are shared: deleting them would revoke every other
// installation connected to the same project. A member that is already absent
// is a no-op, so Delete is idempotent.
func (gcp *GCP) Delete(ctx context.Context) error {
	number, err := gcp.VerifyProject(ctx)
	if err != nil {
		return err
	}

	member := principalFor(number, gcp.tenantId, gcp.installationId)
	for _, role := range projectRoles {
		binding := provider.Binding{Role: role, Member: member}
		if err := gcp.client.RemoveProjectBinding(ctx, gcp.project, binding); err != nil {
			return classify(err)
		}
	}
	gcp.Info("revoked: project bindings", "member", member)
	return nil
}

// assertProviderIsOurs refuses to touch a provider of the fixed name that
// trusts a different issuer. EnsureOIDCProvider patches whatever it finds, so
// without this an object belonging to another deployment would be adopted and
// rewritten on a name collision alone.
func (gcp *GCP) assertProviderIsOurs(ctx context.Context, pool provider.PoolSpec, number string) error {
	existing, err := gcp.client.GetOIDCProvider(ctx, pool, providerID)
	if err != nil {
		return classify(err)
	}
	if existing == nil || existing.Oidc == nil {
		return nil // nothing there yet, or nothing to disagree with
	}
	if existing.Oidc.IssuerUri == gcp.issuer.URL() {
		return nil
	}
	return &ProviderNotOursError{
		Name:          existing.Name,
		IssuerWanted:  gcp.issuer.URL(),
		IssuerFound:   existing.Oidc.IssuerUri,
		PoolID:        poolID,
		ProviderID:    providerID,
		ProjectNumber: number,
	}
}

// spec builds the pool and provider this project should converge to. Neither
// depends on the installation: that distinction lives in the IAM binding.
func (gcp *GCP) spec(projectNumber string) (*provider.PoolSpec, *provider.OIDCProviderSpec) {
	pool := &provider.PoolSpec{
		Project:     gcp.project,
		PoolID:      poolID,
		DisplayName: "formae AI Cloud",
		Description: "Federated identities from formae AI Cloud",
	}

	oidcProvider := &provider.OIDCProviderSpec{
		ProviderID:  providerID,
		DisplayName: "formae ai Cloud OIDC",
		IssuerURI:   gcp.issuer.URL(),
		AttributeMapping: map[string]string{
			"google.subject": "assertion.sub",
		},
		AttributeCondition: subjectNamespaceCondition(),
		// Pinned rather than left to the server's default. The audience in the
		// minted token is this exact resource name, and a default that
		// materialized a different spelling would fail the exchange in a way
		// that reads like an unrelated auth error.
		AllowedAudiences: []string{providerName(projectNumber)},
	}

	return pool, oidcProvider
}

// subjectNamespaceCondition is the CEL expression Google evaluates against an
// incoming assertion. It admits every subject this issuer mints and nothing
// else.
func subjectNamespaceCondition() string {
	return fmt.Sprintf("google.subject.startsWith(%q)", subjectNamespace)
}

// providerName is the canonical resource name of the shared provider.
//
// oox/gcpname parses this same form, and pins the identical literal in its own
// tests. The two are deliberately not sharing code: if both sides derived the
// string from one helper, a test that they agree would prove nothing about
// whether Google accepts it.
func providerName(projectNumber string) string {
	return fmt.Sprintf(
		"//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, poolID, providerID)
}

// principalFor is the IAM member string for one installation's federated
// identity in this project's pool.
func principalFor(projectNumber, tenantId, installationId string) string {
	return provider.SubjectPrincipal(projectNumber, "global", poolID,
		provx.Subject(tenantId, installationId))
}
