package gcp

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// golden is the provider resource name this provisioner must produce for the
// fake's project number. It is written out literally, and oox/gcpname pins the
// same literal in its own tests. The duplication is deliberate: if both sides
// derived the string from one shared helper, a test that they agree would
// prove nothing about whether Google accepts it.
const golden = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"

func TestCreateGrantsEditorAndProjectIamAdmin(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")

	mustCreate(t, g)

	if len(f.setPolicyBodies) == 0 {
		t.Fatal("no IAM policy was submitted")
	}
	final := f.setPolicyBodies[len(f.setPolicyBodies)-1].Policy
	member := principalFor(f.projectNumber, "tenant-a", "install-1")

	for _, role := range []string{"roles/editor", "roles/resourcemanager.projectIamAdmin"} {
		if !contains(membersOf(final, role), member) {
			t.Errorf("role %s does not bind %s; policy = %+v", role, member, final.Bindings)
		}
	}
	// The invalid id this replaces must be gone.
	for _, b := range final.Bindings {
		if b.Role == "roles/project.Owner" {
			t.Errorf("policy still binds the non-existent role roles/project.Owner")
		}
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")

	mustCreate(t, g)
	before := len(f.setPolicyBodies)
	mustCreate(t, g)

	if len(f.setPolicyBodies) != before {
		t.Errorf("second Create submitted %d more policy writes, want 0",
			len(f.setPolicyBodies)-before)
	}
	if len(f.patchedProviders) != 0 {
		t.Errorf("second Create patched the provider: %v", f.patchedProviders)
	}
}

// TestSecondInstallationIsAdditive is the multi-installation regression: the
// AWS path deliberately supports connecting one account to several
// installations, and a fixed provider name with a single-subject condition
// would let the second connect silently revoke the first.
func TestSecondInstallationIsAdditive(t *testing.T) {
	f := newFakeGoogle()

	mustCreate(t, newTestGCP(t, f, "tenant-a", "install-1"))
	mustCreate(t, newTestGCP(t, f, "tenant-a", "install-2"))

	final := f.setPolicyBodies[len(f.setPolicyBodies)-1].Policy
	first := principalFor(f.projectNumber, "tenant-a", "install-1")
	second := principalFor(f.projectNumber, "tenant-a", "install-2")

	for _, role := range []string{"roles/editor", "roles/resourcemanager.projectIamAdmin"} {
		members := membersOf(final, role)
		if !contains(members, first) {
			t.Errorf("role %s lost the first installation's member; members = %v", role, members)
		}
		if !contains(members, second) {
			t.Errorf("role %s is missing the second installation's member; members = %v", role, members)
		}
	}

	// The provider must not have been rewritten for the second installation.
	if len(f.patchedProviders) != 0 {
		t.Errorf("connecting a second installation patched the shared provider: %v", f.patchedProviders)
	}
}

// TestSetIamPolicyPreservesUnrelatedBindings watches the submitted request
// rather than the fake's stored state, because the fake stores verbatim: a
// destructive whole-policy replace would be visible here and nowhere else.
func TestSetIamPolicyPreservesUnrelatedBindings(t *testing.T) {
	f := newFakeGoogle()
	f.policy = &cloudresourcemanager.Policy{
		Version: 3,
		Etag:    "etag-0",
		Bindings: []*cloudresourcemanager.Binding{
			{Role: "roles/viewer", Members: []string{"user:someone@example.com"}},
		},
	}
	g := newTestGCP(t, f, "tenant-a", "install-1")
	mustCreate(t, g)

	// Every submission must carry the unrelated binding through, not just the
	// last one: a destructive replace at any step loses it.
	for i, body := range f.setPolicyBodies {
		if !contains(membersOf(body.Policy, "roles/viewer"), "user:someone@example.com") {
			t.Errorf("submission %d dropped an unrelated binding: %+v", i, body.Policy.Bindings)
		}
	}
	// Each write echoes the etag from its own read, so the first submission
	// carries the etag the project started with. Asserting that on the last
	// submission would be wrong: one binding per role means two
	// read-modify-write cycles, and the second reads what the first wrote.
	if got := f.setPolicyBodies[0].Policy.Etag; got != "etag-0" {
		t.Errorf("first submitted policy etag = %q, want the one that was read (etag-0)", got)
	}
}

func TestProviderConditionIsNamespaceScoped(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")
	mustCreate(t, g)

	var created *struct {
		Condition string
		Issuer    string
		Audiences []string
	}
	for _, p := range f.createdProviders {
		created = &struct {
			Condition string
			Issuer    string
			Audiences []string
		}{p.AttributeCondition, p.Oidc.IssuerUri, p.Oidc.AllowedAudiences}
	}
	if created == nil {
		t.Fatal("no provider was created")
	}

	// Asserting the exact string matters: a provider with no condition at all
	// would satisfy "two installations produce the same spec".
	want := `google.subject.startsWith("fai:")`
	if created.Condition != want {
		t.Errorf("attribute condition = %q, want %q", created.Condition, want)
	}
	if strings.Contains(created.Condition, "install-1") {
		t.Errorf("condition pins a single installation: %q", created.Condition)
	}
}

func TestSubjectNamespacePredicate(t *testing.T) {
	// The condition is a CEL string evaluated by Google, so the unit under
	// test here is the predicate's intent: ours match, foreign do not.
	ours := []string{"fai:tenant-a/install-1", "fai:tenant-b/install-9"}
	foreign := []string{"", "faiX:tenant/install", "other:tenant/install", "FAI:tenant/install", " fai:tenant/install"}

	for _, s := range ours {
		if !strings.HasPrefix(s, subjectNamespace) {
			t.Errorf("subject %q should be in namespace %q", s, subjectNamespace)
		}
	}
	for _, s := range foreign {
		if strings.HasPrefix(s, subjectNamespace) {
			t.Errorf("subject %q should not be in namespace %q", s, subjectNamespace)
		}
	}
}

func TestCreateSetsAllowedAudienceToTheProviderName(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")
	mustCreate(t, g)

	for _, p := range f.createdProviders {
		if len(p.Oidc.AllowedAudiences) != 1 || p.Oidc.AllowedAudiences[0] != golden {
			t.Errorf("AllowedAudiences = %v, want exactly [%s]", p.Oidc.AllowedAudiences, golden)
		}
	}
}

func TestCreateReturnsTheProviderName(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")

	res := mustCreate(t, g)
	if res.ProviderName != golden {
		t.Errorf("ProviderName = %q, want %q", res.ProviderName, golden)
	}
	if res.ProjectNumber != "123456789012" {
		t.Errorf("ProjectNumber = %q, want 123456789012", res.ProjectNumber)
	}
}

// TestProviderTrustsTheIssuerItWasGiven holds the issuer to the caller's. It
// is the whole reason New takes one: an issuer resolved inside this package
// would provision trust for whatever this build was compiled against, no
// matter which issuer the control plane named.
func TestProviderTrustsTheIssuerItWasGiven(t *testing.T) {
	f := newFakeGoogle()
	mustCreate(t, newTestGCP(t, f, "tenant-a", "install-1"))

	for _, p := range f.createdProviders {
		if p.Oidc.IssuerUri != testIssuer {
			t.Errorf("provider issuerUri = %q, want %q", p.Oidc.IssuerUri, testIssuer)
		}
	}
	if len(f.createdProviders) == 0 {
		t.Fatal("no provider was created")
	}
}

// TestRefusesAnIssuerThatIsNotACanonicalOrigin fails the construction rather
// than the provisioning: an issuer with a path or a port cannot be compared
// against what Google stores, so accepting one here would defer the failure to
// a provider that silently never matches.
func TestRefusesAnIssuerThatIsNotACanonicalOrigin(t *testing.T) {
	f := newFakeGoogle()
	for _, issuer := range []string{"", "http://issuer.test.example", "https://issuer.test.example/", "https://issuer.test.example:8443"} {
		if _, err := newTestGCPWithIssuer(t, f, "tenant-a", "install-1", issuer); err == nil {
			t.Errorf("New accepted issuer %q", issuer)
		}
	}
}

// TestRefusesAProviderThatIsNotOurs guards the shared singleton: the pool and
// provider ids are fixed, so an object of that name belonging to a different
// deployment must not be adopted and rewritten.
func TestRefusesAProviderThatIsNotOurs(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")
	mustCreate(t, g)

	// Someone repoints the provider at a different issuer.
	for name, p := range f.providers {
		p.Oidc.IssuerUri = "https://issuer.someone-else.example"
		f.providers[name] = p
	}
	f.patchedProviders = map[string]*iam.WorkloadIdentityPoolProvider{}

	_, err := g.Create(t.Context())
	if err == nil {
		t.Fatal("Create adopted a provider naming a foreign issuer")
	}
	var notOurs *ProviderNotOursError
	if !errors.As(err, &notOurs) {
		t.Errorf("error = %T (%v), want *ProviderNotOursError", err, err)
	}
	if len(f.patchedProviders) != 0 {
		t.Errorf("a foreign provider was patched: %v", f.patchedProviders)
	}
}

func TestDeleteRemovesOnlyThisInstallationsMember(t *testing.T) {
	f := newFakeGoogle()
	mustCreate(t, newTestGCP(t, f, "tenant-a", "install-1"))
	mustCreate(t, newTestGCP(t, f, "tenant-a", "install-2"))

	if err := newTestGCP(t, f, "tenant-a", "install-2").Delete(t.Context()); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	final := f.setPolicyBodies[len(f.setPolicyBodies)-1].Policy
	first := principalFor(f.projectNumber, "tenant-a", "install-1")
	second := principalFor(f.projectNumber, "tenant-a", "install-2")

	for _, role := range []string{"roles/editor", "roles/resourcemanager.projectIamAdmin"} {
		members := membersOf(final, role)
		if !contains(members, first) {
			t.Errorf("role %s lost the surviving installation's member: %v", role, members)
		}
		if contains(members, second) {
			t.Errorf("role %s still binds the deleted installation: %v", role, members)
		}
	}

	// The shared pool and provider must survive: deleting them would revoke
	// every other installation on the project.
	if f.sawRequest("DELETE /v1/projects") {
		t.Errorf("Delete removed the shared pool or provider; requests = %v", f.requests)
	}
	if len(f.pools) == 0 || len(f.providers) == 0 {
		t.Errorf("pool or provider was removed: pools=%d providers=%d", len(f.pools), len(f.providers))
	}
}

func TestVerifyProjectDistinguishesAuthFromPermission(t *testing.T) {
	f := newFakeGoogle()
	g := newTestGCP(t, f, "tenant-a", "install-1")

	number, err := g.VerifyProject(t.Context())
	if err != nil {
		t.Fatalf("VerifyProject: %v", err)
	}
	if number != "123456789012" {
		t.Errorf("project number = %q, want 123456789012", number)
	}
}

func TestAPIDisabledIsClassifiedThroughThePublicOperation(t *testing.T) {
	f := newFakeGoogle()
	f.poolCreateError = &googleError{
		status: 403, code: 403,
		message: "Identity and Access Management (IAM) API has not been used in project 123456789012 before or it is disabled",
		reason:  "SERVICE_DISABLED", domain: "googleapis.com",
	}
	g := newTestGCP(t, f, "tenant-a", "install-1")

	_, err := g.Create(t.Context())
	if err == nil {
		t.Fatal("Create succeeded with the IAM API disabled")
	}
	var disabled *APIDisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("error = %T (%v), want *APIDisabledError", err, err)
	}
	if disabled.API == "" {
		t.Error("APIDisabledError does not name the API to enable")
	}
}

func TestPermissionDeniedIsNotMistakenForADisabledAPI(t *testing.T) {
	f := newFakeGoogle()
	f.poolCreateError = &googleError{
		status: 403, code: 403,
		message: "Permission 'iam.workloadIdentityPools.create' denied",
		reason:  "IAM_PERMISSION_DENIED", domain: "iam.googleapis.com",
	}
	g := newTestGCP(t, f, "tenant-a", "install-1")

	_, err := g.Create(t.Context())
	if err == nil {
		t.Fatal("Create succeeded without permission")
	}
	var disabled *APIDisabledError
	if errors.As(err, &disabled) {
		t.Errorf("a permission denial was reported as a disabled API: %v", err)
	}
	var denied *PermissionDeniedError
	if !errors.As(err, &denied) {
		t.Errorf("error = %T (%v), want *PermissionDeniedError", err, err)
	}
}
