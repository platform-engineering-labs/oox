package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/platform-engineering-labs/oox/oidcx"
)

const Audience = "api://AzureADTokenExchange"

// AzureConfig describes the Entra workload identity federation target.
type Config struct {
	TenantID string

	// ClientID is the app registration or user-assigned managed identity that
	// carries the federated identity credential.
	ClientID string

	scopes []string
}

func NewConfig(scopes []string) Config {
	if len(scopes) == 0 {
		scopes = []string{"https://management.azure.com/.default"}
	}

	return Config{scopes: scopes}
}

func (c Config) Scopes() []string {
	return c.scopes
}

// Credential returns an azidentity credential.
//
// Entra's flow differs from AWS and GCP: there is no separate exchange endpoint.
// The token is presented as the client assertion in an ordinary client
// credentials grant, standing in for the client secret the app registration
// would otherwise need. The callback is invoked on every refresh.
//
// opts is passed straight through to azidentity.NewClientAssertionCredential.
// Production callers pass nil; it exists so a test can inject a transport
// (ClientOptions.Transport) and disable Entra instance discovery
// (DisableInstanceDiscovery), which together keep a token acquisition
// entirely offline.
func Credential(client oidcx.Client, cfg Config, opts *azidentity.ClientAssertionCredentialOptions) (*azidentity.ClientAssertionCredential, error) {
	return azidentity.NewClientAssertionCredential(
		cfg.TenantID,
		cfg.ClientID,
		func(ctx context.Context) (string, error) {
			return client.Token(ctx, Audience)
		},
		opts,
	)
}
