package osv

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Parse decodes an OSV record from `data` and dispatches the
// `database_specific` / `ecosystem_specific` blobs into typed structs
// chosen by the ecosystem segment carved from `path`. `path` is the
// upstream file path layout `<...>/osv/<ecosystem>/<file>.json`; the
// segment immediately following `osv/` selects the dispatch table.
//
// Unknown ecosystems return an error rather than silently routing into
// a default — once a new ecosystem appears upstream the typed schema
// must be extended explicitly so the round-trip verifier stays honest.
func Parse(path string, data []byte) (Record, error) {
	eco, err := ecosystemFromPath(path)
	if err != nil {
		return Record{}, err
	}
	d, ok := dispatch[eco]
	if !ok {
		return Record{}, fmt.Errorf("osv: unknown ecosystem %q (path=%q)", eco, path)
	}
	return decode(data, d)
}

// ecosystemDispatch wires the four concrete struct factories for one
// upstream ecosystem. Each factory returns a fresh pointer so the
// per-record decode never reuses state across calls.
type ecosystemDispatch struct {
	top    func() TopSpecific
	affEco func() AffectedEcoSpec
	affDB  func() AffectedDBSpec
	rngDB  func() RangeDBSpec
}

// dispatch routes ecosystem dir name → factory set. Populated by
// ecosystem_<name>.go init functions.
var dispatch = map[string]ecosystemDispatch{}

// register is called from each ecosystem_<name>.go init() to plug its
// factories into the dispatch table. Duplicate registration panics so
// renames or accidental copy-paste in the per-ecosystem files do not
// silently overwrite an existing entry.
func register(eco string, d ecosystemDispatch) {
	if _, ok := dispatch[eco]; ok {
		panic("osv: duplicate ecosystem registration: " + eco)
	}
	dispatch[eco] = d
}

// ecosystemFromPath returns the ecosystem directory name from an upstream
// OSV path (`<root>/osv/<ecosystem>/<file>.json`). It accepts both `/`
// and `\\` separators so the package stays platform-agnostic, and
// preserves the directory name verbatim (spaces and dots included) —
// the dispatch table keys mirror the on-disk dir names so downstream
// consumers (walker, writer) can route with the same string.
func ecosystemFromPath(path string) (string, error) {
	p := strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if seg == "osv" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("osv: cannot derive ecosystem from path %q", path)
}

// decode is the per-ecosystem JSON pipeline. It unmarshals into a
// shadow struct that mirrors Record but holds the four blob fields as
// json.RawMessage; once that succeeds it instantiates the concrete
// specific structs from the dispatch entry and unmarshals each blob
// into its destination. The shadow exists because Go's encoding/json
// cannot assign into an interface field directly.
func decode(data []byte, d ecosystemDispatch) (Record, error) {
	type shadowAffected struct {
		Package           *Package        `json:"package,omitempty"`
		Severity          []Severity      `json:"severity,omitempty"`
		Ranges            []shadowRange   `json:"ranges,omitempty"`
		Versions          []string        `json:"versions,omitempty"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
		DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
	}
	type shadow struct {
		Record
		Affected         []shadowAffected `json:"affected,omitempty"`
		DatabaseSpecific json.RawMessage  `json:"database_specific,omitempty"`
	}
	var s shadow
	if err := json.Unmarshal(data, &s); err != nil {
		return Record{}, fmt.Errorf("osv: unmarshal: %w", err)
	}
	rec := s.Record
	rec.Affected = nil
	if len(s.DatabaseSpecific) > 0 && !isJSONNull(s.DatabaseSpecific) {
		v := d.top()
		if err := json.Unmarshal(s.DatabaseSpecific, v); err != nil {
			return Record{}, fmt.Errorf("osv: top database_specific: %w", err)
		}
		rec.DatabaseSpecific = v
	}
	for _, sa := range s.Affected {
		a := Affected{
			Package:  sa.Package,
			Severity: sa.Severity,
			Versions: sa.Versions,
		}
		for _, sr := range sa.Ranges {
			rg := Range{Type: sr.Type, Repo: sr.Repo, Events: sr.Events}
			if len(sr.DatabaseSpecific) > 0 && !isJSONNull(sr.DatabaseSpecific) {
				v := d.rngDB()
				if err := json.Unmarshal(sr.DatabaseSpecific, v); err != nil {
					return Record{}, fmt.Errorf("osv: range database_specific: %w", err)
				}
				rg.DatabaseSpecific = v
			}
			a.Ranges = append(a.Ranges, rg)
		}
		if len(sa.EcosystemSpecific) > 0 && !isJSONNull(sa.EcosystemSpecific) {
			v := d.affEco()
			if err := json.Unmarshal(sa.EcosystemSpecific, v); err != nil {
				return Record{}, fmt.Errorf("osv: affected ecosystem_specific: %w", err)
			}
			a.EcosystemSpecific = v
		}
		if len(sa.DatabaseSpecific) > 0 && !isJSONNull(sa.DatabaseSpecific) {
			v := d.affDB()
			if err := json.Unmarshal(sa.DatabaseSpecific, v); err != nil {
				return Record{}, fmt.Errorf("osv: affected database_specific: %w", err)
			}
			a.DatabaseSpecific = v
		}
		rec.Affected = append(rec.Affected, a)
	}
	return rec, nil
}

// shadowRange mirrors Range during decode, holding database_specific as
// raw bytes so the per-ecosystem dispatch can hydrate it afterwards.
type shadowRange struct {
	Type             string          `json:"type"`
	Repo             string          `json:"repo,omitempty"`
	Events           []Event         `json:"events"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

func isJSONNull(b json.RawMessage) bool {
	s := strings.TrimSpace(string(b))
	return s == "null"
}
