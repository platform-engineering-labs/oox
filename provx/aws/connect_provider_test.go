package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func newTestAWS(t *testing.T, f *fakeIAM) *AWS {
	t.Helper()
	a, err := newWithClients(context.Background(),
		&fakeSTS{account: "111122223333", arn: "arn:aws:iam::111122223333:user/x"},
		f, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnsureProviderCreates(t *testing.T) {
	var gotURL string
	var gotClients []string
	f := &fakeIAM{t: t, createOIDCProvider: func(in *iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
		gotURL = awssdk.ToString(in.Url)
		gotClients = in.ClientIDList
		return &iam.CreateOpenIDConnectProviderOutput{}, nil
	}}
	out, err := newTestAWS(t, f).ensureProvider(context.Background())
	if err != nil || out != ProviderCreated {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if gotURL != "https://issuer.test.example" || len(gotClients) != 1 || gotClients[0] != "sts.amazonaws.com" {
		t.Fatalf("create input: url=%q clients=%v", gotURL, gotClients)
	}
}

func TestEnsureProviderExistsValid(t *testing.T) {
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(in *iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return &iam.GetOpenIDConnectProviderOutput{
				Url:          awssdk.String("issuer.test.example"),
				ClientIDList: []string{"sts.amazonaws.com"},
			}, nil
		},
	}
	out, err := newTestAWS(t, f).ensureProvider(context.Background())
	if err != nil || out != ProviderExisted {
		t.Fatalf("out=%v err=%v", out, err)
	}
	// addClientID nil => any call would have failed the test.
}

func TestEnsureProviderAddsClientID(t *testing.T) {
	added := false
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return &iam.GetOpenIDConnectProviderOutput{Url: awssdk.String("issuer.test.example"), ClientIDList: []string{"other"}}, nil
		},
		addClientID: func(in *iam.AddClientIDToOpenIDConnectProviderInput) (*iam.AddClientIDToOpenIDConnectProviderOutput, error) {
			if awssdk.ToString(in.ClientID) != "sts.amazonaws.com" {
				t.Fatalf("added %q", awssdk.ToString(in.ClientID))
			}
			added = true
			return &iam.AddClientIDToOpenIDConnectProviderOutput{}, nil
		},
	}
	out, err := newTestAWS(t, f).ensureProvider(context.Background())
	if err != nil || out != ProviderExisted || !added {
		t.Fatalf("out=%v err=%v added=%v", out, err, added)
	}
}

func TestEnsureProviderURLMismatchConflicts(t *testing.T) {
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return &iam.GetOpenIDConnectProviderOutput{Url: awssdk.String("evil.example.com"), ClientIDList: []string{"sts.amazonaws.com"}}, nil
		},
	}
	_, err := newTestAWS(t, f).ensureProvider(context.Background())
	var conflict *ProviderConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want ProviderConflictError, got %v", err)
	}
}

func TestEnsureProviderGetFailureKeepsCause(t *testing.T) {
	cause := &types.NoSuchEntityException{}
	f := &fakeIAM{t: t,
		createOIDCProvider: func(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
			return nil, &types.EntityAlreadyExistsException{}
		},
		getOIDCProvider: func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
			return nil, cause
		},
	}
	_, err := newTestAWS(t, f).ensureProvider(context.Background())
	var conflict *ProviderConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want ProviderConflictError, got %v", err)
	}
	var nse *types.NoSuchEntityException
	if !errors.As(err, &nse) {
		t.Fatal("SDK cause must stay discoverable through Unwrap")
	}
}
