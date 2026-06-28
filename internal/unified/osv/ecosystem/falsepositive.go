package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/masahiro331/wisteria/internal/unified/osv"
)

// Ecosystems whose only distinguishing payload is a `false_positive`
// boolean on `affected[].ranges[].database_specific` (Chainguard,
// Wolfi, MinimOS) and Rocky Linux's `yum_repository` flag.

// ============================================================
// Chainguard
// ============================================================

type RecordChainguard struct {
	osv.Record
	Affected         []AffectedChainguard `json:"affected,omitempty"`
	DatabaseSpecific TopChainguard        `json:"database_specific,omitzero"`
}

func (r *RecordChainguard) Base() *osv.Record  { return &r.Record }
func (r *RecordChainguard) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedChainguard struct {
	osv.AffectedBase
	Ranges            []RangeChainguard     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoChainguard `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBChainguard  `json:"database_specific,omitzero"`
}

type RangeChainguard struct {
	osv.RangeBase
	DatabaseSpecific RangeDBChainguard `json:"database_specific,omitzero"`
}

type TopChainguard struct{}

func (TopChainguard) IsZero() bool { return true }

type AffectedEcoChainguard struct{}

func (AffectedEcoChainguard) IsZero() bool { return true }

type AffectedDBChainguard struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBChainguard) IsZero() bool { return a == AffectedDBChainguard{} }

type RangeDBChainguard struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (r RangeDBChainguard) IsZero() bool { return r == RangeDBChainguard{} }

func NewRecordChainguard(r io.Reader) (*RecordChainguard, error) {
	var rec RecordChainguard
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Chainguard: %w", err)
	}
	rec.Ecosystem = osv.EcosystemChainguard
	return &rec, nil
}

// ============================================================
// Wolfi
// ============================================================

type RecordWolfi struct {
	osv.Record
	Affected         []AffectedWolfi `json:"affected,omitempty"`
	DatabaseSpecific TopWolfi        `json:"database_specific,omitzero"`
}

func (r *RecordWolfi) Base() *osv.Record  { return &r.Record }
func (r *RecordWolfi) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedWolfi struct {
	osv.AffectedBase
	Ranges            []RangeWolfi     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoWolfi `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBWolfi  `json:"database_specific,omitzero"`
}

type RangeWolfi struct {
	osv.RangeBase
	DatabaseSpecific RangeDBWolfi `json:"database_specific,omitzero"`
}

type TopWolfi struct{}

func (TopWolfi) IsZero() bool { return true }

type AffectedEcoWolfi struct{}

func (AffectedEcoWolfi) IsZero() bool { return true }

type AffectedDBWolfi struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBWolfi) IsZero() bool { return a == AffectedDBWolfi{} }

type RangeDBWolfi struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (r RangeDBWolfi) IsZero() bool { return r == RangeDBWolfi{} }

func NewRecordWolfi(r io.Reader) (*RecordWolfi, error) {
	var rec RecordWolfi
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Wolfi: %w", err)
	}
	rec.Ecosystem = osv.EcosystemWolfi
	return &rec, nil
}

// ============================================================
// MinimOS
// ============================================================

type RecordMinimOS struct {
	osv.Record
	Affected         []AffectedMinimOS `json:"affected,omitempty"`
	DatabaseSpecific TopMinimOS        `json:"database_specific,omitzero"`
}

func (r *RecordMinimOS) Base() *osv.Record  { return &r.Record }
func (r *RecordMinimOS) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedMinimOS struct {
	osv.AffectedBase
	Ranges            []RangeMinimOS     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoMinimOS `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBMinimOS  `json:"database_specific,omitzero"`
}

type RangeMinimOS struct {
	osv.RangeBase
	DatabaseSpecific RangeDBMinimOS `json:"database_specific,omitzero"`
}

type TopMinimOS struct{}

func (TopMinimOS) IsZero() bool { return true }

type AffectedEcoMinimOS struct{}

func (AffectedEcoMinimOS) IsZero() bool { return true }

type AffectedDBMinimOS struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBMinimOS) IsZero() bool { return a == AffectedDBMinimOS{} }

type RangeDBMinimOS struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (r RangeDBMinimOS) IsZero() bool { return r == RangeDBMinimOS{} }

func NewRecordMinimOS(r io.Reader) (*RecordMinimOS, error) {
	var rec RecordMinimOS
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse MinimOS: %w", err)
	}
	rec.Ecosystem = osv.EcosystemMinimOS
	return &rec, nil
}

// ============================================================
// Rocky Linux
// ============================================================

type RecordRockyLinux struct {
	osv.Record
	Affected         []AffectedRockyLinux `json:"affected,omitempty"`
	DatabaseSpecific TopRockyLinux        `json:"database_specific,omitzero"`
}

func (r *RecordRockyLinux) Base() *osv.Record  { return &r.Record }
func (r *RecordRockyLinux) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedRockyLinux struct {
	osv.AffectedBase
	Ranges            []RangeRockyLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRockyLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRockyLinux  `json:"database_specific,omitzero"`
}

type RangeRockyLinux struct {
	osv.RangeBase
	DatabaseSpecific RangeDBRockyLinux `json:"database_specific,omitzero"`
}

type TopRockyLinux struct{}

func (TopRockyLinux) IsZero() bool { return true }

type AffectedEcoRockyLinux struct{}

func (AffectedEcoRockyLinux) IsZero() bool { return true }

type AffectedDBRockyLinux struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBRockyLinux) IsZero() bool { return a == AffectedDBRockyLinux{} }

// RangeDBRockyLinux carries the `yum_repository` flag (e.g. "CRB",
// "AppStream") that Rocky attaches to a subset of advisories.
type RangeDBRockyLinux struct {
	YumRepository string `json:"yum_repository,omitempty"`
}

func (r RangeDBRockyLinux) IsZero() bool { return r == RangeDBRockyLinux{} }

func NewRecordRockyLinux(r io.Reader) (*RecordRockyLinux, error) {
	var rec RecordRockyLinux
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse RockyLinux: %w", err)
	}
	rec.Ecosystem = osv.EcosystemRockyLinux
	return &rec, nil
}
