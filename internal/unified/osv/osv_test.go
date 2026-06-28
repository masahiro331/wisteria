package osv

import "testing"

// TestEcosystemFromString covers verbatim and space-normalized forms.
func TestEcosystemFromString(t *testing.T) {
	cases := []struct {
		in   string
		want Ecosystem
	}{
		{"PyPI", EcosystemPyPI},
		{"Red Hat", EcosystemRedHat},
		{"Red_Hat", EcosystemRedHat}, // walker uses the underscore form
		{"crates.io", EcosystemCratesIO},
	}
	for _, tc := range cases {
		got, err := EcosystemFromString(tc.in)
		if err != nil {
			t.Errorf("EcosystemFromString(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EcosystemFromString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := EcosystemFromString("Unknown"); err == nil {
		t.Error("EcosystemFromString must error on unknown name")
	}
}
