package main

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestCollectMissing_DetectsNestedReferences pins the §7 "1 byte not
// lost" rule from the tool side: a non-empty raw value at any depth
// that the typed schema lacks must show up in the diff. This is the
// regression check for issue #56 — the bug there was that
// problemTypes[].descriptions[].references was silently dropped, and
// the natural question is "would schema-coverage have caught it?".
//
// The answer is yes provided a sampled file actually contained a
// non-empty references[] at that depth; this test shows the detection
// path itself is intact regardless of which files happen to be
// sampled.
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

// TestCollectMissing_EmptyArrayIsAbsentEquivalent guards the existing
// noise-suppression rule: an empty references[] in raw with no field
// in typed must NOT be reported. Issue #56's empirical impact note
// hinges on this — the tool didn't trip on real data because the
// sampled records happened to have no entries at that depth, not
// because the detection logic was broken.
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
