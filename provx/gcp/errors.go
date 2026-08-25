package gcp

import (
	"errors"
	"fmt"

	"google.golang.org/api/googleapi"
)

// ProviderNotOursError: an object with the fixed pool/provider name already
// exists and names a different OIDC issuer, so it belongs to something else -
// another formae deployment, a staging issuer, or a user's own federation that
// happens to share the name. Nothing was mutated.
//
// The pool and provider are shared singletons per project, so adopting one on
// a name match alone would silently rewrite somebody else's trust.
type ProviderNotOursError struct {
	Name          string
	IssuerWanted  string
	IssuerFound   string
	PoolID        string
	ProviderID    string
	ProjectNumber string
}

func (e *ProviderNotOursError) Error() string {
	return fmt.Sprintf(
		"workload identity provider %s already exists and trusts issuer %s, not %s; refusing to modify it",
		e.Name, e.IssuerFound, e.IssuerWanted)
}

// APIDisabledError: a required Google API is not enabled on the project.
// Common on a project that has never used workload identity federation, and
// the remedy is a single command, so it is worth telling the operator which
// API rather than surfacing a bare 403.
//
// formae does not enable the API itself: that is a mutation nobody asked for.
type APIDisabledError struct {
	API   string
	Cause error
}

func (e *APIDisabledError) Error() string {
	return fmt.Sprintf("the %s API is not enabled on this project; enable it and re-run", e.API)
}

func (e *APIDisabledError) Unwrap() error { return e.Cause }

// PermissionDeniedError: the credentials reached Google and were refused. This
// is deliberately distinct from APIDisabledError, because both arrive as HTTP
// 403 and the remedies have nothing in common: one needs a permission grant,
// the other needs a service enabled.
type PermissionDeniedError struct {
	Permission string
	Cause      error
}

func (e *PermissionDeniedError) Error() string {
	if e.Permission != "" {
		return fmt.Sprintf("permission denied: %s", e.Permission)
	}
	return fmt.Sprintf("permission denied: %v", e.Cause)
}

func (e *PermissionDeniedError) Unwrap() error { return e.Cause }

// OrgPolicyError: an organization policy or service-perimeter rule refused the
// call. Neither a permission grant nor enabling an API will fix it, so it must
// not be reported as either.
type OrgPolicyError struct {
	Reason string
	Cause  error
}

func (e *OrgPolicyError) Error() string {
	return fmt.Sprintf("an organization policy refused this call (%s)", e.Reason)
}

func (e *OrgPolicyError) Unwrap() error { return e.Cause }

// ProjectUnreachableError: the project could not be read. Either it does not
// exist, or these credentials cannot see it. This is what tells a caller that
// re-authenticating will not help, because the principal is not the problem.
type ProjectUnreachableError struct {
	Project string
	Cause   error
}

func (e *ProjectUnreachableError) Error() string {
	return fmt.Sprintf("project %q could not be read with these credentials", e.Project)
}

func (e *ProjectUnreachableError) Unwrap() error { return e.Cause }

// The reason codes Google returns in an ErrorInfo detail. Classification reads
// these, never the HTTP status or the message text: 403 alone is equally a
// disabled service, a missing permission, a VPC Service Controls perimeter, or
// an org-policy denial, and telling an operator to enable an API that is
// already on wastes their time in the most confusing way available.
const (
	reasonServiceDisabled = "SERVICE_DISABLED"
	reasonIamDenied       = "IAM_PERMISSION_DENIED"
	reasonOrgPolicy       = "ORG_POLICY_VIOLATION"
	reasonVPCSC           = "SECURITY_POLICY_VIOLATED"
)

// classify maps a Google API failure onto one of the typed errors above,
// leaving anything it does not recognise untouched rather than guessing.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) {
		return err
	}

	reason, domain := errorInfo(gerr)
	switch reason {
	case reasonServiceDisabled:
		api := domain
		if api == "" || api == "googleapis.com" {
			api = serviceFromMessage(gerr.Message)
		}
		return &APIDisabledError{API: api, Cause: err}
	case reasonIamDenied:
		return &PermissionDeniedError{Permission: permissionFromMessage(gerr.Message), Cause: err}
	case reasonOrgPolicy, reasonVPCSC:
		return &OrgPolicyError{Reason: reason, Cause: err}
	}
	return err
}

// errorInfo digs the google.rpc.ErrorInfo reason and domain out of a
// googleapi.Error. The generated clients surface Details as decoded JSON, and
// older responses carry the reason on Errors instead, so both are read.
func errorInfo(gerr *googleapi.Error) (reason, domain string) {
	for _, d := range gerr.Details {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["@type"].(string)
		if t != "" && !containsFold(t, "ErrorInfo") {
			continue
		}
		r, _ := m["reason"].(string)
		dom, _ := m["domain"].(string)
		if r != "" {
			return r, dom
		}
	}
	for _, e := range gerr.Errors {
		if e.Reason != "" {
			return e.Reason, ""
		}
	}
	return "", ""
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (indexFold(s, sub) >= 0)
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// serviceFromMessage pulls the API host out of the standard SERVICE_DISABLED
// message, which names it even when the error domain does not. Falls back to
// the IAM API, which is the one this package needs first.
func serviceFromMessage(msg string) string {
	for _, candidate := range []string{
		"iam.googleapis.com",
		"cloudresourcemanager.googleapis.com",
		"sts.googleapis.com",
	} {
		if indexFold(msg, candidate) >= 0 {
			return candidate
		}
	}
	return "iam.googleapis.com"
}

// permissionFromMessage extracts the quoted permission name Google includes in
// a denial, for a message that says what to grant.
func permissionFromMessage(msg string) string {
	start := -1
	for i := 0; i < len(msg); i++ {
		if msg[i] == '\'' {
			if start < 0 {
				start = i + 1
				continue
			}
			return msg[start:i]
		}
	}
	return ""
}
