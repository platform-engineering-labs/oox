// Package gcpname parses and formats the resource name of a Google Cloud
// workload identity pool provider.
//
// The name matters twice over: it is the coordinate a cloud connection is
// registered under, and it is the audience of the identity token minted for
// that connection. Anything that validates it with a prefix match admits a
// host that merely begins with the right characters, and anything that spells
// it slightly differently from the provisioned form produces a token that
// silently fails to exchange. So the grammar is exact, the parse is total, and
// Parse followed by String is the identity function on every accepted input.
//
// The package is deliberately dependency-free: its consumers are a
// provisioner, a plugin, a credential broker and a CLI, in three repositories.
package gcpname

import (
	"errors"
	"fmt"
	"strings"
)

// prefix is the literal start of every provider resource name. The trailing
// "/projects/" is part of it on purpose: without it, "//iam.googleapis.com"
// also matches "//iam.googleapis.com.evil/...".
const prefix = "//iam.googleapis.com/projects/"

const (
	locationsSegment = "/locations/global/workloadIdentityPools/"
	providersSegment = "/providers/"

	// idMin and idMax are Google's own bounds for a pool or provider id.
	idMin = 4
	idMax = 32

	// reservedIDPrefix is refused by Google for user-created ids.
	reservedIDPrefix = "gcp-"
)

// Name is a parsed provider resource name. A zero Name is not valid; obtain
// one from Parse.
type Name struct {
	// ProjectNumber is the numeric project id, never the project id string:
	// IAM member strings for workload identity pools require the number.
	ProjectNumber string
	Pool          string
	Provider      string
}

// String renders the canonical resource name.
func (n Name) String() string {
	return prefix + n.ProjectNumber + locationsSegment + n.Pool + providersSegment + n.Provider
}

// Audience is the token audience for this provider. It is the resource name
// itself; the method exists so callers say what they mean at the call site,
// and so the two uses cannot drift apart later.
func (n Name) Audience() string { return n.String() }

// InvalidNameError reports a string that is not a canonical provider resource
// name. Reason says which rule failed, for a message a human can act on.
type InvalidNameError struct {
	Input  string
	Reason string
}

func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("not a workload identity provider resource name (%s)", e.Reason)
}

func invalid(input, reason string) error {
	return &InvalidNameError{Input: input, Reason: reason}
}

// isInvalidName is the predicate the tests use; callers use errors.As.
func isInvalidName(err error) bool {
	var e *InvalidNameError
	return errors.As(err, &e)
}

// Parse validates s against the canonical grammar and returns its parts.
//
// Accepted, and nothing else:
//
//	//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
//
// where <number> is ASCII digits with no leading zero, and <pool> and
// <provider> follow Google's id rule. Percent-encoding, query strings,
// fragments, trailing slashes, extra segments, whitespace and non-ASCII bytes
// all fail, because each of them is a way to write a name that Google would
// canonicalize differently from what was provisioned.
func Parse(s string) (Name, error) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return Name{}, invalid(s, "wrong prefix: must start with "+prefix)
	}

	number, rest, ok := strings.Cut(rest, locationsSegment)
	if !ok {
		return Name{}, invalid(s, "missing "+strings.Trim(locationsSegment, "/")+" segment")
	}
	if err := validProjectNumber(number); err != nil {
		return Name{}, invalid(s, err.Error())
	}

	pool, provider, ok := strings.Cut(rest, providersSegment)
	if !ok {
		return Name{}, invalid(s, "missing providers segment")
	}
	if err := validID(pool); err != nil {
		return Name{}, invalid(s, "pool id: "+err.Error())
	}
	if err := validID(provider); err != nil {
		return Name{}, invalid(s, "provider id: "+err.Error())
	}

	return Name{ProjectNumber: number, Pool: pool, Provider: provider}, nil
}

// validProjectNumber accepts ASCII digits with no leading zero. A leading zero
// is refused rather than trimmed: two spellings of one number would mean two
// spellings of one audience.
func validProjectNumber(s string) error {
	if s == "" {
		return errors.New("project number is empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return errors.New("project number must be digits, not a project id")
		}
	}
	if s[0] == '0' {
		return errors.New("project number must not have a leading zero")
	}
	return nil
}

// validID applies Google's rule for a pool or provider id: 4 to 32 characters
// of lowercase letters, digits and hyphens, not starting with the reserved
// "gcp-" prefix.
func validID(s string) error {
	if len(s) < idMin || len(s) > idMax {
		return fmt.Errorf("must be %d to %d characters, got %d", idMin, idMax, len(s))
	}
	if strings.HasPrefix(s, reservedIDPrefix) {
		return fmt.Errorf("must not start with the reserved %q prefix", reservedIDPrefix)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return errors.New("may contain only lowercase letters, digits and hyphens")
	}
	return nil
}
