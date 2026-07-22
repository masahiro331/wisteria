package osv

import (
	"encoding/json"
	"reflect"
	"testing"
)

// wrapper exercises StringOrList the way schema structs use it:
// omitzero so an absent field stays absent on re-marshal.
type solWrapper struct {
	Source StringOrList `json:"source,omitzero"`
}

func TestStringOrList_RoundTripPreservesShape(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "bare string", in: `{"source":"CPE_RANGE"}`, want: []string{"CPE_RANGE"}},
		{name: "array", in: `{"source":["CPE_RANGE","REFERENCES"]}`, want: []string{"CPE_RANGE", "REFERENCES"}},
		{name: "single-element array stays an array", in: `{"source":["CPE_RANGE"]}`, want: []string{"CPE_RANGE"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var w solWrapper
			if err := json.Unmarshal([]byte(tc.in), &w); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !reflect.DeepEqual(w.Source.Values(), tc.want) {
				t.Errorf("Values = %v, want %v", w.Source.Values(), tc.want)
			}
			out, err := json.Marshal(w)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(out) != tc.in {
				t.Errorf("round-trip = %s, want %s", out, tc.in)
			}
		})
	}
}

func TestStringOrList_AbsentStaysAbsent(t *testing.T) {
	var w solWrapper
	if err := json.Unmarshal([]byte(`{}`), &w); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{}` {
		t.Errorf("absent field re-marshaled as %s", out)
	}
}

func TestStringOrList_RejectsOtherShapes(t *testing.T) {
	var w solWrapper
	if err := json.Unmarshal([]byte(`{"source":42}`), &w); err == nil {
		t.Fatal("expected error for non-string, non-array value")
	}
}

func TestStringOrList_PresentEmptyStringRoundTrips(t *testing.T) {
	var w solWrapper
	if err := json.Unmarshal([]byte(`{"source":""}`), &w); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"source":""}` {
		t.Errorf("present-empty string re-marshaled as %s", out)
	}
}

func TestStringOrList_NullIsTreatedAsAbsent(t *testing.T) {
	var w solWrapper
	if err := json.Unmarshal([]byte(`{"source":null}`), &w); err != nil {
		t.Fatal(err)
	}
	if out, _ := json.Marshal(w); string(out) != `{}` {
		t.Errorf("null re-marshaled as %s, want {} (null ≡ absent per coverage rule)", out)
	}
}
