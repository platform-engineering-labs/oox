package azure

import (
	"strings"
	"testing"
)

// The ownership marker is a cross-repo contract: the azure plugin's built-in
// discovery filter matches this exact string, and it is spelled identically on
// AWS and GCP. Nothing else in this package would notice the key changing,
// because everything refers to it through the constant, so the literal is
// pinned here.
func TestOwnerTagKeyMatchesTheMarkerDiscoveryLooksFor(t *testing.T) {
	if ownerTagKey != "formae-owned" {
		t.Fatalf("ownerTagKey = %q, want %q", ownerTagKey, "formae-owned")
	}
	if ownerTagValue != "true" {
		t.Fatalf("ownerTagValue = %q, want %q", ownerTagValue, "true")
	}
}

// GCP label keys admit only lowercase letters, digits, underscores and hyphens,
// so a colon would make the same marker unspellable there and split the three
// clouds onto different keys.
func TestOwnerTagKeyIsLegalAsAGCPLabelKey(t *testing.T) {
	if strings.ContainsAny(ownerTagKey, ":.") {
		t.Fatalf("ownerTagKey %q must avoid punctuation GCP label keys reject", ownerTagKey)
	}
}
