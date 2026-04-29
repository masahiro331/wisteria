package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestCollectMissing_DetectsNestedReferences pins the §7 "1 byte not
// lost" rule from the tool side: a non-empty raw value at any depth
// that the typed schema lacks must show up in the diff. The test
// guards the detection path itself, independent of which files happen
// to be sampled when the tool runs against a real sources tree.
func TestCollectMissing_DetectsNestedReferences(t *testing.T) {
	rawJSON := []byte(`{
		"containers": {
			"cna": {
				"problemTypes": [
					{
						"descriptions": [
							{
								"lang": "en",
								"description": "x",
								"references": [
									{"url": "https://example.com/r1"}
								]
							}
						]
					}
				]
			}
		}
	}`)
	// typed mirror simulates a schema that knows everything except the
	// inner references[]. The leaf is an empty object so collectMissing
	// reaches the right depth; the missing key then surfaces in `out`.
	typedJSON := []byte(`{
		"containers": {
			"cna": {
				"problemTypes": [
					{
						"descriptions": [
							{"lang": "en", "description": "x"}
						]
					}
				]
			}
		}
	}`)

	var rawAny, typedAny any
	if err := json.Unmarshal(rawJSON, &rawAny); err != nil {
		t.Fatalf("raw unmarshal: %v", err)
	}
	if err := json.Unmarshal(typedJSON, &typedAny); err != nil {
		t.Fatalf("typed unmarshal: %v", err)
	}

	var out []string
	collectMissing("", normalize(rawAny), normalize(typedAny), &out)

	want := "containers.cna.problemTypes[].descriptions[].references"
	if !slices.Contains(out, want) {
		t.Fatalf("missing path %q not detected; got %v", want, out)
	}
}

// TestCollectMissing_EmptyArrayIsAbsentEquivalent guards the
// noise-suppression rule: an empty references[] in raw with no field
// in typed must NOT be reported (an empty array carries no information
// beyond its bare presence).
func TestCollectMissing_EmptyArrayIsAbsentEquivalent(t *testing.T) {
	rawJSON := []byte(`{
		"problemTypes": [
			{"descriptions": [{"lang": "en", "references": []}]}
		]
	}`)
	typedJSON := []byte(`{
		"problemTypes": [
			{"descriptions": [{"lang": "en"}]}
		]
	}`)

	var rawAny, typedAny any
	if err := json.Unmarshal(rawJSON, &rawAny); err != nil {
		t.Fatalf("raw unmarshal: %v", err)
	}
	if err := json.Unmarshal(typedJSON, &typedAny); err != nil {
		t.Fatalf("typed unmarshal: %v", err)
	}

	var out []string
	collectMissing("", normalize(rawAny), normalize(typedAny), &out)
	if len(out) != 0 {
		t.Errorf("empty references[] should be absent-equivalent, got %v", out)
	}
}

// TestCollectDiff_ScalarValueMismatch — the strict verifier must flag a
// scalar value the typed schema rewrote, not just keys it dropped. A
// silent value change (e.g. number→string coercion or truncation in a
// custom Marshal) is exactly the bug pattern the round-trip check is
// supposed to catch.
func TestCollectDiff_ScalarValueMismatch(t *testing.T) {
	raw := mustAny(t, `{"a": "hello"}`)
	typed := mustAny(t, `{"a": "world"}`)

	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) == 0 {
		t.Fatalf("scalar mismatch must be flagged, got empty diff")
	}
	if !containsPath(out, "a") {
		t.Fatalf("expected diff at %q, got %v", "a", out)
	}
}

// TestCollectDiff_ArrayLengthMismatch — losing the trailing array
// element is the most common omitempty regression. The strict diff
// must report it (current collectMissing pads typed with the first
// element and lets it slip).
func TestCollectDiff_ArrayLengthMismatch(t *testing.T) {
	raw := mustAny(t, `{"xs": [1, 2, 3]}`)
	typed := mustAny(t, `{"xs": [1, 2]}`)

	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) == 0 {
		t.Fatalf("length mismatch must be flagged, got empty diff")
	}
}

// TestCollectDiff_AbsentEquivalent — null / [] / {} / 0001 timestamp
// on the raw side stay absent-equivalent under strict diff too, so we
// don't drown in upstream noise (e.g. Debian advisories that emit
// literal zero timestamps).
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

// TestCollectDiff_ExtraKeyOnTypedSide — if the typed schema injects a
// key the raw input never had, that's a fabrication, not a faithful
// round-trip. Strict diff flags it as `+key` so the report distinguishes
// drops (no prefix) from inventions (`+`).
func TestCollectDiff_ExtraKeyOnTypedSide(t *testing.T) {
	raw := mustAny(t, `{"a": 1}`)
	typed := mustAny(t, `{"a": 1, "b": 2}`)

	var out []string
	collectDiff("", raw, typed, &out)
	if !containsPath(out, "+b") {
		t.Fatalf("expected fabricated key diff containing %q, got %v", "+b", out)
	}
}

// TestCollectDiff_TimestampPrecisionEquivalence — Go's time.Time marshals
// fractional seconds with extra zero padding ("...327Z" → "...327000000Z").
// Same instant, different textual form. Must NOT diff, otherwise every
// upstream record with a sub-second timestamp drowns the report.
func TestCollectDiff_TimestampPrecisionEquivalence(t *testing.T) {
	raw := mustAny(t, `{"a": "2009-11-20T18:30:00.327Z"}`)
	typed := mustAny(t, `{"a": "2009-11-20T18:30:00.327000000Z"}`)

	var out []string
	collectDiff("", raw, typed, &out)
	if len(out) != 0 {
		t.Errorf("equivalent timestamps must not diff, got %v", out)
	}
}

// TestCollectDiff_NumberFidelity — JSON numbers must compare by their
// decoded form, not their textual form. json.Unmarshal into any decodes
// every JSON number as float64 by default, so 1 vs 1.0 must NOT diff.
// This guards against accidentally over-reporting just because the
// re-marshaled output normalized number formatting.
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
