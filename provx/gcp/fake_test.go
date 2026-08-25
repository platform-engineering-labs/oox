package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// fakeGoogle answers the IAM and Cloud Resource Manager calls this package
// makes, and records every request it received. Tests assert on the recorded
// requests rather than on the fake's own state: a fake that merged IAM policy
// members by itself would hide a destructive whole-policy replace, which is
// exactly the bug the binding tests exist to catch.
type fakeGoogle struct {
	mu sync.Mutex

	// requests is every (method, path) pair seen, in order.
	requests []string
	// setPolicyBodies is the decoded body of each SetIamPolicy call, in order.
	setPolicyBodies []*cloudresourcemanager.SetIamPolicyRequest
	// createdProviders and patchedProviders record provider writes by name.
	createdProviders map[string]*iam.WorkloadIdentityPoolProvider
	patchedProviders map[string]*iam.WorkloadIdentityPoolProvider

	// State the fake serves back.
	projectNumber   string
	pools           map[string]*iam.WorkloadIdentityPool
	providers       map[string]*iam.WorkloadIdentityPoolProvider
	policy          *cloudresourcemanager.Policy
	poolCreateError *googleError
}

type googleError struct {
	status  int
	code    int
	message string
	reason  string
	domain  string
}

func newFakeGoogle() *fakeGoogle {
	return &fakeGoogle{
		projectNumber:    "123456789012",
		pools:            map[string]*iam.WorkloadIdentityPool{},
		providers:        map[string]*iam.WorkloadIdentityPoolProvider{},
		createdProviders: map[string]*iam.WorkloadIdentityPoolProvider{},
		patchedProviders: map[string]*iam.WorkloadIdentityPoolProvider{},
		policy:           &cloudresourcemanager.Policy{Etag: "etag-0", Version: 3},
	}
}

func (f *fakeGoogle) record(method, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, method+" "+path)
}

func (f *fakeGoogle) sawRequest(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func (f *fakeGoogle) countRequests(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

// RoundTrip routes on path. IAM is /v1/..., Cloud Resource Manager is /v3/...,
// so one endpoint serves both.
func (f *fakeGoogle) RoundTrip(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	f.record(req.Method, path)

	switch {
	case strings.HasPrefix(path, "/v3/projects/") && strings.HasSuffix(path, ":getIamPolicy"):
		f.mu.Lock()
		defer f.mu.Unlock()
		return jsonResponse(200, f.policy)

	case strings.HasPrefix(path, "/v3/projects/") && strings.HasSuffix(path, ":setIamPolicy"):
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var in cloudresourcemanager.SetIamPolicyRequest
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		// Record and serve independent copies. Sharing one object would let a
		// later call mutate an earlier recorded request, which silently
		// rewrites the history the tests assert on.
		f.setPolicyBodies = append(f.setPolicyBodies, &cloudresourcemanager.SetIamPolicyRequest{
			Policy: clonePolicy(in.Policy),
		})
		// Store verbatim. The fake never merges: whatever the caller sent is
		// what the project's policy becomes, which is how the real API behaves.
		next := clonePolicy(in.Policy)
		next.Etag = "etag-" + strconv.Itoa(len(f.setPolicyBodies))
		f.policy = next
		return jsonResponse(200, f.policy)

	case strings.HasPrefix(path, "/v3/projects/"):
		f.mu.Lock()
		defer f.mu.Unlock()
		return jsonResponse(200, &cloudresourcemanager.Project{
			Name: "projects/" + f.projectNumber, ProjectId: "test-project",
		})

	case strings.Contains(path, "/workloadIdentityPools/") && strings.Contains(path, "/providers"):
		return f.providerRoute(req, path)

	case strings.Contains(path, "/workloadIdentityPools"):
		return f.poolRoute(req, path)
	}
	return jsonResponse(404, map[string]any{"error": map[string]any{"code": 404, "message": "not found"}})
}

func (f *fakeGoogle) poolRoute(req *http.Request, path string) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if req.Method == http.MethodPost {
		if f.poolCreateError != nil {
			return errorResponse(f.poolCreateError)
		}
		id := req.URL.Query().Get("workloadIdentityPoolId")
		name := strings.TrimPrefix(path, "/v1/") + "/" + id
		f.pools[name] = &iam.WorkloadIdentityPool{Name: name, State: "ACTIVE"}
		return jsonResponse(200, &iam.Operation{Done: true})
	}
	name := strings.TrimPrefix(path, "/v1/")
	if p, ok := f.pools[name]; ok {
		return jsonResponse(200, p)
	}
	return jsonResponse(404, map[string]any{"error": map[string]any{"code": 404, "message": "pool not found"}})
}

func (f *fakeGoogle) providerRoute(req *http.Request, path string) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	name := strings.TrimPrefix(path, "/v1/")
	switch req.Method {
	case http.MethodPost:
		var in iam.WorkloadIdentityPoolProvider
		if err := decodeBody(req, &in); err != nil {
			return nil, err
		}
		id := req.URL.Query().Get("workloadIdentityPoolProviderId")
		full := name + "/" + id
		in.Name = full
		in.State = "ACTIVE"
		f.providers[full] = &in
		f.createdProviders[full] = &in
		return jsonResponse(200, &iam.Operation{Done: true})
	case http.MethodPatch:
		var in iam.WorkloadIdentityPoolProvider
		if err := decodeBody(req, &in); err != nil {
			return nil, err
		}
		in.Name = name
		in.State = "ACTIVE"
		f.providers[name] = &in
		f.patchedProviders[name] = &in
		return jsonResponse(200, &iam.Operation{Done: true})
	default:
		if p, ok := f.providers[name]; ok {
			return jsonResponse(200, p)
		}
		return jsonResponse(404, map[string]any{"error": map[string]any{"code": 404, "message": "provider not found"}})
	}
}

func decodeBody(req *http.Request, v any) error {
	if req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

func jsonResponse(status int, v any) (*http.Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(b))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func errorResponse(e *googleError) (*http.Response, error) {
	payload := map[string]any{
		"error": map[string]any{
			"code":    e.code,
			"message": e.message,
			"status":  "PERMISSION_DENIED",
			"details": []any{
				map[string]any{
					"@type":  "type.googleapis.com/google.rpc.ErrorInfo",
					"reason": e.reason,
					"domain": e.domain,
				},
			},
		},
	}
	return jsonResponse(e.status, payload)
}

// newTestGCP builds a GCP provisioner wired to the fake.
func newTestGCP(t *testing.T, f *fakeGoogle, tenant, installation string) *GCP {
	t.Helper()
	g, err := New(t.Context(), discardLogger(), "test-project", tenant, installation,
		option.WithoutAuthentication(),
		option.WithEndpoint("https://example.invalid/"),
		option.WithHTTPClient(&http.Client{Transport: f}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func mustCreate(t *testing.T, g *GCP) *Result {
	t.Helper()
	res, err := g.Create(t.Context())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return res
}

func membersOf(p *cloudresourcemanager.Policy, role string) []string {
	for _, b := range p.Bindings {
		if b.Role == role {
			return b.Members
		}
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// clonePolicy deep-copies the parts of a policy these tests inspect.
func clonePolicy(p *cloudresourcemanager.Policy) *cloudresourcemanager.Policy {
	if p == nil {
		return nil
	}
	out := &cloudresourcemanager.Policy{Etag: p.Etag, Version: p.Version}
	for _, b := range p.Bindings {
		nb := &cloudresourcemanager.Binding{Role: b.Role, Condition: b.Condition}
		nb.Members = append(nb.Members, b.Members...)
		out.Bindings = append(out.Bindings, nb)
	}
	return out
}
