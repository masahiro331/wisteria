package cwe

import (
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		// Weakness entry.
		{id: "CWE-79", want: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
		// Category entry — CNAs occasionally reference these.
		{id: "CWE-310", want: "Cryptographic Issues"},
		// Unknown / malformed forms upstream data actually contains.
		{id: "CWE-999999", want: ""},
		{id: "n/a", want: ""},
		{id: "", want: ""},
	}
	for _, tc := range tests {
		if got := Name(tc.id); got != tc.want {
			t.Errorf("Name(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestCatalogIsPopulated(t *testing.T) {
	if len(names) < 900 {
		t.Fatalf("catalog has %d entries; expected the full MITRE catalog (>900)", len(names))
	}
	if CatalogVersion == "" {
		t.Fatal("CatalogVersion is empty")
	}
	for id := range names {
		if !strings.HasPrefix(id, "CWE-") {
			t.Fatalf("catalog key %q is not CWE-prefixed", id)
		}
	}
}
