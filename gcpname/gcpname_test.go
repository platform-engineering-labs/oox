package gcpname

import "testing"

// golden is a literal, well-formed provider resource name. It is deliberately
// written out here rather than built from constants: provx/gcp pins the same
// literal in its own tests, and a shared helper on both sides would let the two
// agree on a value Google rejects.
const golden = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"

func TestParsesTheGoldenName(t *testing.T) {
	got, err := Parse(golden)
	if err != nil {
		t.Fatalf("Parse(golden) failed: %v", err)
	}
	if got.ProjectNumber != "123456789012" {
		t.Errorf("ProjectNumber = %q, want 123456789012", got.ProjectNumber)
	}
	if got.Pool != "formae-ai" {
		t.Errorf("Pool = %q, want formae-ai", got.Pool)
	}
	if got.Provider != "formae-ai" {
		t.Errorf("Provider = %q, want formae-ai", got.Provider)
	}
	if got.String() != golden {
		t.Errorf("String() = %q, want %q", got.String(), golden)
	}
	if got.Audience() != golden {
		t.Errorf("Audience() = %q, want %q", got.Audience(), golden)
	}
}

// TestParseRejectsPrefixLookalike is the reason this package exists: a prefix
// match on "//iam.googleapis.com" admits a host that merely starts with it.
func TestParseRejectsPrefixLookalike(t *testing.T) {
	lookalikes := []string{
		"//iam.googleapis.com.evil/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai",
		"//iam.googleapis.com.attacker.example/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		"//iam.googleapis.comprojects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai",
		"//iam.googleapis.co/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai",
		"//evil.com//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai",
	}
	for _, in := range lookalikes {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want rejection", in)
		}
	}
}

func TestParseRejectsHTTPSForm(t *testing.T) {
	// GCP's default allowed audience includes an https:// spelling, but the
	// token audience oidcx/gcp requests is the // form. Accepting both here
	// would let a caller mint a token that does not match what was provisioned.
	https := "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"
	if _, err := Parse(https); err == nil {
		t.Errorf("Parse(%q) succeeded, want rejection", https)
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	bad := []struct{ name, in string }{
		{"empty", ""},
		{"prefix only", "//iam.googleapis.com/projects/"},
		{"trailing slash", golden + "/"},
		{"extra segment", golden + "/extra"},
		{"query string", golden + "?x=1"},
		{"fragment", golden + "#f"},
		{"percent-encoded separator", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools%2Fformae-ai/providers/formae-ai"},
		{"percent-encoded pool", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae%2Dai/providers/formae-ai"},
		{"leading whitespace", " " + golden},
		{"trailing whitespace", golden + " "},
		{"embedded newline", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/formae\n-ai"},
		// Cyrillic small a, written as an escape so the case cannot silently
		// become ASCII when this file is edited or copied.
		{"homoglyph in pool", nameWith("form\u0430e-ai", "formae-ai")},
		{"homoglyph in provider", nameWith("formae-ai", "form\u0430e-ai")},
		{"empty project number", "//iam.googleapis.com/projects//locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"empty pool", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools//providers/formae-ai"},
		{"empty provider", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/providers/"},
		{"non-global location", "//iam.googleapis.com/projects/123456789012/locations/us-central1/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"missing locations segment", "//iam.googleapis.com/projects/123456789012/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"project id not number", "//iam.googleapis.com/projects/my-project/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"project number leading zero", "//iam.googleapis.com/projects/0123456789/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"project number zero", "//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"},
		{"pools segment misspelled", "//iam.googleapis.com/projects/123456789012/locations/global/workloadidentitypools/formae-ai/providers/formae-ai"},
		{"providers segment misspelled", "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/formae-ai/provider/formae-ai"},
	}
	for _, c := range bad {
		if _, err := Parse(c.in); err == nil {
			t.Errorf("%s: Parse(%q) succeeded, want rejection", c.name, c.in)
		}
	}
}

func TestParseRejectsIdsOutsideGCPRules(t *testing.T) {
	// GCP: 4-32 characters, lowercase letters, digits and hyphens, and the id
	// must not start with "gcp-".
	bad := []string{"abc", "gcp-pool", "Formae-AI", "formae_ai", "formae.ai",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} // 33 chars
	for _, id := range bad {
		if _, err := Parse(nameWith(id, "formae-ai")); err == nil {
			t.Errorf("Parse with pool %q succeeded, want rejection", id)
		}
		if _, err := Parse(nameWith("formae-ai", id)); err == nil {
			t.Errorf("Parse with provider %q succeeded, want rejection", id)
		}
	}
}

func TestBoundariesPerComponent(t *testing.T) {
	// The round-trip test alone would pass for a parser that accepts too much
	// and reproduces it faithfully, so each component is checked at its edges.
	good := []string{"abcd", "a123", "0abc", "a-b-c",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 32 chars
		"gcpx-pool",                        // "gcp-" is reserved; "gcpx-" is not
	}
	for _, id := range good {
		if _, err := Parse(nameWith(id, id)); err != nil {
			t.Errorf("Parse with id %q failed: %v", id, err)
		}
	}

	numbers := []struct {
		in string
		ok bool
	}{
		{"1", true}, {"9", true}, {"123456789012", true},
		{"12345678901234567890", true},
		{"0", false}, {"01", false}, {"1a", false}, {"1_2", false},
	}
	for _, c := range numbers {
		in := "//iam.googleapis.com/projects/" + c.in +
			"/locations/global/workloadIdentityPools/formae-ai/providers/formae-ai"
		_, err := Parse(in)
		if c.ok && err != nil {
			t.Errorf("Parse with project number %q failed: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("Parse with project number %q succeeded, want rejection", c.in)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := []string{
		golden,
		nameWith("abcd", "abcd"),
		nameWith("a-b-c", "gcpx-pool"),
		"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/prov",
	}
	for _, in := range inputs {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", in, err)
		}
		if got.String() != in {
			t.Errorf("round trip: Parse(%q).String() = %q", in, got.String())
		}
	}
}

func TestErrorsAreTyped(t *testing.T) {
	// Callers classify failures; nobody should have to match on message text.
	if _, err := Parse("nonsense"); err == nil {
		t.Fatal("Parse(nonsense) succeeded")
	} else if !isInvalidName(err) {
		t.Errorf("Parse(nonsense) returned %T, want an InvalidNameError", err)
	}
}

func nameWith(pool, provider string) string {
	return "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/" +
		pool + "/providers/" + provider
}
