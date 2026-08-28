package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTS struct {
	account, arn string
	err          error
}

func (f *fakeSTS) GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: &f.account, Arn: &f.arn}, nil
}

// testIssuer is deliberately not the production issuer. The production code
// takes the issuer as a parameter, and the assertions below pin it as it
// appears in the provider URL and the trust policy — but written with the
// production value they would pass just as well against an issuer resolved
// from provx.Endpoint, which is the regression they exist to catch.
const testIssuer = "https://issuer.test.example"

func TestNewVerifiesAccount(t *testing.T) {
	_, err := newWithClients(context.Background(),
		&fakeSTS{account: "444455556666", arn: "arn:aws:iam::444455556666:user/x"},
		nil, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
	var mismatch *AccountMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want AccountMismatchError, got %v", err)
	}
	if mismatch.Actual != "444455556666" {
		t.Fatalf("actual = %q (pointer-format regression)", mismatch.Actual)
	}
}

func TestNewRejectsNonCommercialPartition(t *testing.T) {
	for _, callerArn := range []string{
		"arn:aws-us-gov:iam::111122223333:user/x",
		"arn:aws-cn:iam::111122223333:user/x",
	} {
		_, err := newWithClients(context.Background(),
			&fakeSTS{account: "111122223333", arn: callerArn},
			nil, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
		if err == nil || !strings.Contains(err.Error(), "partition") {
			t.Fatalf("%s: want partition error, got %v", callerArn, err)
		}
	}
}

func TestNewRejectsMalformedCallerArn(t *testing.T) {
	for _, callerArn := range []string{"", "arn:aws:", "not-an-arn"} {
		_, err := newWithClients(context.Background(),
			&fakeSTS{account: "111122223333", arn: callerArn},
			nil, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
		if err == nil {
			t.Fatalf("%q: malformed caller ARN must be rejected", callerArn)
		}
	}
}

func TestNewWrapsSTSError(t *testing.T) {
	sentinel := errors.New("token expired")
	_, err := newWithClients(context.Background(), &fakeSTS{err: sentinel},
		nil, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
	if !errors.Is(err, sentinel) {
		t.Fatalf("STS error must be wrapped with %%w, got %v", err)
	}
}

func TestNewRejectsBadIssuer(t *testing.T) {
	_, err := newWithClients(context.Background(),
		&fakeSTS{account: "111122223333", arn: "arn:aws:iam::111122223333:user/x"},
		nil, "111122223333", "fai:t/i", "fai-t-i", "http://not-https")
	if err == nil {
		t.Fatal("bad issuer must be rejected")
	}
}

func TestNewAcceptsMatchingAccount(t *testing.T) {
	a, err := newWithClients(context.Background(),
		&fakeSTS{account: "111122223333", arn: "arn:aws:iam::111122223333:user/x"},
		nil, "111122223333", "fai:t/i", "fai-t-i", testIssuer)
	if err != nil || a == nil {
		t.Fatalf("err=%v", err)
	}
}
