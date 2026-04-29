package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCollectDiff_DropsAreFlagged — a key present in raw but missing
// in typed must surface unless the value is absent-equivalent.
func TestCollectDiff_DropsAreFlagged(t *testing.T) {
	raw := mustAny(t, `{
		"containers": {"cna": {"problemTypes": [
			{"descriptions": [{"lang": "en", "references": [{"url": "https://example/r"}]}]}
		]}}
	}`)
	typed := mustAny(t, `{
		"containers": {"cna": {"problemTypes": [
			{"descriptions": [{"lang": "en"}]}
		]}}
	}`)
	var out []string
	collectDiff("", raw, typed, &out)
	want := "containers.cna.problemTypes[].descriptions[].references"
	if !containsExact(out, want) {
		t.Errorf("missing path %q not detected; got %v", want, out)
	}
}

// TestCollectDiff_EmptyArrayIsAbsentEquivalent — an empty array
// in raw with no field in typed must NOT be reported.
func TestCollectDiff_EmptyArrayIsAbsentEquivalent(t *testing.T) {
	raw := mustAny(t, `{"problemTypes": [{"descriptions": [{"lang": "en", "references": []}]}]}`)
	typed := mustAny(t, `{"problemTypes": [{"descriptions": [{"lang": "en"}]}]}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) != 0 {
		t.Errorf("empty references[] should be absent-equivalent, got %v", out)
	}
}

// TestCollectDiff_ScalarValueMismatch — strict diff must flag a
// scalar value the typed schema rewrote, not just keys it dropped.
func TestCollectDiff_ScalarValueMismatch(t *testing.T) {
	raw := mustAny(t, `{"a": "hello"}`)
	typed := mustAny(t, `{"a": "world"}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if !containsPath(out, "a") {
		t.Errorf("expected diff at %q, got %v", "a", out)
	}
}

// TestCollectDiff_ArrayLengthMismatch — losing a trailing array
// element is a common omitempty regression. Strict diff flags it.
func TestCollectDiff_ArrayLengthMismatch(t *testing.T) {
	raw := mustAny(t, `{"xs": [1, 2, 3]}`)
	typed := mustAny(t, `{"xs": [1, 2]}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) == 0 {
		t.Errorf("length mismatch must be flagged, got empty diff")
	}
}

// TestCollectDiff_AbsentEquivalent — null / [] / {} / 0001 timestamp
// stay absent-equivalent under strict diff.
func TestCollectDiff_AbsentEquivalent(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"null", `{"a": null}`},
		{"empty array", `{"a": []}`},
		{"empty object", `{"a": {}}`},
		{"zero timestamp", `{"a": "0001-01-01T00:00:00Z"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustAny(t, tc.raw)
			typed := mustAny(t, `{}`)
			var out []string
			collectDiff("", raw, typed, &out)
			if len(out) != 0 {
				t.Errorf("absent-equivalent raw should not diff, got %v", out)
			}
		})
	}
}

// TestCollectDiff_ExtraKeyOnTypedSide — typed schema fabricating a
// key the raw input never had is a faithfulness violation; strict
// diff flags it as `+key`.
func TestCollectDiff_ExtraKeyOnTypedSide(t *testing.T) {
	raw := mustAny(t, `{"a": 1}`)
	typed := mustAny(t, `{"a": 1, "b": 2}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if !containsExact(out, "+b") {
		t.Errorf("expected fabricated key diff %q, got %v", "+b", out)
	}
}

// TestCollectDiff_TimestampPrecisionEquivalence — Go's time.Time
// re-marshals fractional seconds with extra zero padding. Same
// instant, different textual form: must NOT diff.
func TestCollectDiff_TimestampPrecisionEquivalence(t *testing.T) {
	raw := mustAny(t, `{"a": "2009-11-20T18:30:00.327Z"}`)
	typed := mustAny(t, `{"a": "2009-11-20T18:30:00.327000000Z"}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) != 0 {
		t.Errorf("equivalent timestamps must not diff, got %v", out)
	}
}

// TestCollectDiff_NumberFidelity — `1` and `1.0` must agree under
// the default `any`-decoding (both decode to float64).
func TestCollectDiff_NumberFidelity(t *testing.T) {
	raw := mustAny(t, `{"a": 1}`)
	typed := mustAny(t, `{"a": 1.0}`)
	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) != 0 {
		t.Errorf("1 and 1.0 must be equal under default decoding, got %v", out)
	}
}

func mustAny(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("unmarshal %q: %v", s, err)
	}
	return v
}

func containsPath(diffs []string, want string) bool {
	for _, d := range diffs {
		if d == want || strings.HasPrefix(d, want+":") {
			return true
		}
	}
	return false
}

func containsExact(diffs []string, want string) bool {
	for _, d := range diffs {
		if d == want {
			return true
		}
	}
	return false
}
