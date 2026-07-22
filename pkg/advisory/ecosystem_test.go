package advisory_test

import (
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/osv"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

// osvEcosystemNames enumerates every name in the internal osv enum by
// walking the constants until String() falls off the table.
func osvEcosystemNames() []string {
	var out []string
	for i := osv.Ecosystem(0); ; i++ {
		s := i.String()
		if strings.HasPrefix(s, "Ecosystem(") {
			return out
		}
		out = append(out, s)
	}
}

// TestEcosystems_MatchOSVEnum guards the public constant list against
// drift: every ecosystem the internal OSV parser knows must have a
// public constant, and every public constant must be a real ecosystem.
func TestEcosystems_MatchOSVEnum(t *testing.T) {
	internal := map[string]bool{}
	for _, name := range osvEcosystemNames() {
		internal[name] = true
	}
	public := map[string]bool{}
	for _, e := range advisory.Ecosystems() {
		public[string(e)] = true
	}

	for name := range internal {
		if !public[name] {
			t.Errorf("internal osv ecosystem %q has no advisory.Ecosystem constant", name)
		}
	}
	for name := range public {
		if !internal[name] {
			t.Errorf("advisory.Ecosystem constant %q is unknown to internal/unified/osv", name)
		}
	}
	if len(public) != len(advisory.Ecosystems()) {
		t.Errorf("Ecosystems() contains duplicates: %d entries, %d unique", len(advisory.Ecosystems()), len(public))
	}
}

func TestEcosystems_ReturnsACopy(t *testing.T) {
	first := advisory.Ecosystems()
	first[0] = "mutated"
	if advisory.Ecosystems()[0] == "mutated" {
		t.Fatal("Ecosystems() must return a copy, not the backing slice")
	}
}

func TestEcosystem_WithSuffix(t *testing.T) {
	tests := []struct {
		base   advisory.Ecosystem
		suffix string
		want   advisory.Ecosystem
	}{
		{base: advisory.EcosystemAlpine, suffix: "v3.17", want: advisory.Ecosystem("Alpine:v3.17")},
		{base: advisory.EcosystemDebian, suffix: "12", want: advisory.Ecosystem("Debian:12")},
		{base: advisory.EcosystemPyPI, suffix: "", want: advisory.EcosystemPyPI},
	}
	for _, tc := range tests {
		if got := tc.base.WithSuffix(tc.suffix); got != tc.want {
			t.Errorf("%q.WithSuffix(%q) = %q, want %q", tc.base, tc.suffix, got, tc.want)
		}
	}
}
