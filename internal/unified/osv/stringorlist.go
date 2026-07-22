package osv

import (
	"encoding/json"
	"fmt"
)

// StringOrList round-trips a JSON value that the upstream corpus emits
// as either a bare string or an array of strings — e.g. GIT range
// `database_specific.cpe` and `database_specific.source` both ship
// `"CPE_RANGE"` and `["CPE_RANGE","REFERENCES"]` shapes at scale. The
// input shape (and bare presence, via Set) is recorded so re-marshaling
// reproduces the original bytes — the round-trip invariant
// tools/schema-coverage enforces.
type StringOrList struct {
	Set    bool
	Single string
	Multi  []string
}

// Values returns the entries regardless of input shape; a bare string
// yields a one-element slice, an unset or empty value yields nil.
func (s StringOrList) Values() []string {
	if s.Multi != nil {
		return s.Multi
	}
	if s.Set && s.Single != "" {
		return []string{s.Single}
	}
	return nil
}

// IsZero reports absence (or JSON null) so `omitzero` fields stay
// absent on re-marshal.
func (s StringOrList) IsZero() bool { return !s.Set }

func (s StringOrList) MarshalJSON() ([]byte, error) {
	if !s.Set {
		return []byte("null"), nil
	}
	if s.Multi != nil {
		return json.Marshal(s.Multi)
	}
	return json.Marshal(s.Single)
}

func (s *StringOrList) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*s = StringOrList{}
		return nil
	}
	switch b[0] {
	case '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = StringOrList{Set: true, Single: v}
		return nil
	case '[':
		var v []string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		if v == nil {
			v = []string{}
		}
		*s = StringOrList{Set: true, Multi: v}
		return nil
	default:
		return fmt.Errorf("osv: string-or-list: unexpected JSON %q", b)
	}
}
