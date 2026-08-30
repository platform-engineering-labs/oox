package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// fakeOIDCClient stands in for the real formae token source. It records the
// context and audience the assertion callback received, so the test can
// prove Credential actually wires the callback through to
// GetToken - not just that it builds without error.
type fakeOIDCClient struct {
	gotCtx      context.Context
	gotAudience string
	token       string
}

func (f *fakeOIDCClient) Token(ctx context.Context, audience string) (string, error) {
	f.gotCtx = ctx
	f.gotAudience = audience
	return f.token, nil
}

type ctxKey struct{}

// fakeEntraTransport answers every HTTP call MSAL's confidential client can
// make for a client-assertion token acquisition - the tenant discovery
// document and the token endpoint itself - entirely in memory. Azure's SDK
// threads ClientOptions.Transport all the way down to the HTTP client MSAL
// is given (confidential.WithHTTPClient), so this is the only seam needed to
// keep the whole exchange offline: nothing here ever opens a socket.
type fakeEntraTransport struct {
	calls []string
}

func jsonResponse(status int, body map[string]any) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func (f *fakeEntraTransport) Do(req *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, req.Method+" "+req.URL.String())

	var resp *http.Response
	switch {
	case req.Method == http.MethodGet:
		// Tenant discovery / instance discovery metadata. Answered so that
		// even if DisableInstanceDiscovery does not suppress every GET this
		// MSAL version might issue, none of them reach a real host.
		resp = jsonResponse(200, map[string]any{
			"token_endpoint":                        "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "private_key_jwt"},
			"issuer":                                "https://login.microsoftonline.com/test-tenant/v2.0",
			"authorization_endpoint":                "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize",
			"tenant_discovery_endpoint":             "https://login.microsoftonline.com/test-tenant/v2.0/.well-known/openid-configuration",
			"api-version":                           "1.1",
			"metadata": []map[string]any{{
				"preferred_network": "login.microsoftonline.com",
				"preferred_cache":   "login.windows.net",
				"aliases":           []string{"login.microsoftonline.com", "login.windows.net"},
			}},
		})
	default:
		// The token endpoint: a client-credentials grant carrying our
		// assertion as client_assertion. The fake does not validate it -
		// this test is about the seam wiring, not Entra's own validation.
		resp = jsonResponse(200, map[string]any{
			"token_type":     "Bearer",
			"expires_in":     3600,
			"ext_expires_in": 3600,
			"access_token":   "fake-access-token",
		})
	}
	resp.Request = req
	return resp, nil
}

// TestCredentialOptionsSeamKeepsTheExchangeOffline proves the options
// parameter Credential now accepts actually reaches the underlying
// azidentity credential: with a fake transport and instance discovery
// disabled, acquiring a token requires no network access at all, and the
// assertion callback fires with the caller's context.
func TestCredentialOptionsSeamKeepsTheExchangeOffline(t *testing.T) {
	client := &fakeOIDCClient{token: "fake-client-assertion-jwt"}
	transport := &fakeEntraTransport{}

	cfg := NewConfig(nil)
	cfg.TenantID = "11111111-1111-1111-1111-111111111111"
	cfg.ClientID = "22222222-2222-2222-2222-222222222222"

	cred, err := Credential(client, cfg, &azidentity.ClientAssertionCredentialOptions{
		ClientOptions:            azcore.ClientOptions{Transport: transport},
		DisableInstanceDiscovery: true,
	})
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "caller-value")
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: cfg.Scopes()})
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok.Token != "fake-access-token" {
		t.Fatalf("Token = %q, want the fake transport's canned token", tok.Token)
	}

	// The literal, not the Audience constant: provx/azure duplicates this
	// exact string on its side of the module boundary and pins it the same
	// way (see the golden test next to tokenAudience in
	// provx/azure/identity_test.go), specifically so that editing this
	// constant alone - without updating provx/azure - fails a test instead
	// of shipping a silent mismatch that breaks federation in production.
	const goldenAudience = "api://AzureADTokenExchange"
	if client.gotAudience != goldenAudience {
		t.Fatalf("assertion callback audience = %q, want the golden literal %q", client.gotAudience, goldenAudience)
	}
	if client.gotCtx == nil || client.gotCtx.Value(ctxKey{}) != "caller-value" {
		t.Fatal("assertion callback did not receive the caller's context")
	}
	// DisableInstanceDiscovery suppresses the global instance-discovery
	// call, but MSAL Go still fetches the tenant-specific OIDC metadata
	// document before the token request - a GET this fake also has to
	// answer, or the exchange would need real network access even with
	// instance discovery off. Asserting the call count pins that: the seam
	// only keeps this offline because the fake handles both requests.
	if len(transport.calls) != 2 {
		t.Fatalf("calls = %v, want exactly the tenant metadata GET and the token POST", transport.calls)
	}
}
