package osv

import (
	"encoding/json"
	"fmt"
	"io"
)

// This file groups ecosystems whose database_specific /
// ecosystem_specific payloads are trivial — typically a single
// `source` URL on each affected entry and nothing else. Each ecosystem
// still gets its own concrete `RecordX` so divergence (a future key
// landing on AlmaLinux only) can grow locally without touching
// neighbors.
//
// Inventory source: tools/osv-inventory full-corpus run.

// ============================================================
// AlmaLinux
// ============================================================

type RecordAlmaLinux struct {
	Record
	Affected         []AffectedAlmaLinux `json:"affected,omitempty"`
	DatabaseSpecific TopAlmaLinux        `json:"database_specific,omitzero"`
}

func (r *RecordAlmaLinux) Base() *Record      { return &r.Record }
func (r *RecordAlmaLinux) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedAlmaLinux struct {
	AffectedBase
	Ranges            []RangeAlmaLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlmaLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlmaLinux  `json:"database_specific,omitzero"`
}

type RangeAlmaLinux struct {
	RangeBase
}

type TopAlmaLinux struct{}

func (TopAlmaLinux) IsZero() bool { return true }

type AffectedEcoAlmaLinux struct{}

func (AffectedEcoAlmaLinux) IsZero() bool { return true }

type AffectedDBAlmaLinux struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBAlmaLinux) IsZero() bool { return a == AffectedDBAlmaLinux{} }

func NewRecordAlmaLinux(r io.Reader) (*RecordAlmaLinux, error) {
	var rec RecordAlmaLinux
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse AlmaLinux: %w", err)
	}
	rec.Ecosystem = EcosystemAlmaLinux
	return &rec, nil
}

// ============================================================
// Alpaquita
// ============================================================

type RecordAlpaquita struct {
	Record
	Affected         []AffectedAlpaquita `json:"affected,omitempty"`
	DatabaseSpecific TopAlpaquita        `json:"database_specific,omitzero"`
}

func (r *RecordAlpaquita) Base() *Record      { return &r.Record }
func (r *RecordAlpaquita) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedAlpaquita struct {
	AffectedBase
	Ranges            []RangeAlpaquita     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlpaquita `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlpaquita  `json:"database_specific,omitzero"`
}

type RangeAlpaquita struct{ RangeBase }

type TopAlpaquita struct{}

func (TopAlpaquita) IsZero() bool { return true }

type AffectedEcoAlpaquita struct{}

func (AffectedEcoAlpaquita) IsZero() bool { return true }

type AffectedDBAlpaquita struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBAlpaquita) IsZero() bool { return a == AffectedDBAlpaquita{} }

func NewRecordAlpaquita(r io.Reader) (*RecordAlpaquita, error) {
	var rec RecordAlpaquita
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Alpaquita: %w", err)
	}
	rec.Ecosystem = EcosystemAlpaquita
	return &rec, nil
}

// ============================================================
// Alpine
// ============================================================

type RecordAlpine struct {
	Record
	Affected         []AffectedAlpine `json:"affected,omitempty"`
	DatabaseSpecific TopAlpine        `json:"database_specific,omitzero"`
}

func (r *RecordAlpine) Base() *Record      { return &r.Record }
func (r *RecordAlpine) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedAlpine struct {
	AffectedBase
	Ranges            []RangeAlpine     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlpine `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlpine  `json:"database_specific,omitzero"`
}

type RangeAlpine struct{ RangeBase }

type TopAlpine struct{}

func (TopAlpine) IsZero() bool { return true }

type AffectedEcoAlpine struct{}

func (AffectedEcoAlpine) IsZero() bool { return true }

type AffectedDBAlpine struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBAlpine) IsZero() bool { return a == AffectedDBAlpine{} }

func NewRecordAlpine(r io.Reader) (*RecordAlpine, error) {
	var rec RecordAlpine
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Alpine: %w", err)
	}
	rec.Ecosystem = EcosystemAlpine
	return &rec, nil
}

// ============================================================
// Azure Linux
// ============================================================

type RecordAzureLinux struct {
	Record
	Affected         []AffectedAzureLinux `json:"affected,omitempty"`
	DatabaseSpecific TopAzureLinux        `json:"database_specific,omitzero"`
}

func (r *RecordAzureLinux) Base() *Record      { return &r.Record }
func (r *RecordAzureLinux) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedAzureLinux struct {
	AffectedBase
	Ranges            []RangeAzureLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAzureLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAzureLinux  `json:"database_specific,omitzero"`
}

type RangeAzureLinux struct{ RangeBase }

type TopAzureLinux struct{}

func (TopAzureLinux) IsZero() bool { return true }

type AffectedEcoAzureLinux struct{}

func (AffectedEcoAzureLinux) IsZero() bool { return true }

type AffectedDBAzureLinux struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBAzureLinux) IsZero() bool { return a == AffectedDBAzureLinux{} }

func NewRecordAzureLinux(r io.Reader) (*RecordAzureLinux, error) {
	var rec RecordAzureLinux
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse AzureLinux: %w", err)
	}
	rec.Ecosystem = EcosystemAzureLinux
	return &rec, nil
}

// ============================================================
// BellSoft Hardened Containers
// ============================================================

type RecordBellSoftHardenedContainers struct {
	Record
	Affected         []AffectedBellSoftHardenedContainers `json:"affected,omitempty"`
	DatabaseSpecific TopBellSoftHardenedContainers        `json:"database_specific,omitzero"`
}

func (r *RecordBellSoftHardenedContainers) Base() *Record      { return &r.Record }
func (r *RecordBellSoftHardenedContainers) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedBellSoftHardenedContainers struct {
	AffectedBase
	Ranges            []RangeBellSoftHardenedContainers     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoBellSoftHardenedContainers `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBBellSoftHardenedContainers  `json:"database_specific,omitzero"`
}

type RangeBellSoftHardenedContainers struct{ RangeBase }

type TopBellSoftHardenedContainers struct{}

func (TopBellSoftHardenedContainers) IsZero() bool { return true }

type AffectedEcoBellSoftHardenedContainers struct{}

func (AffectedEcoBellSoftHardenedContainers) IsZero() bool { return true }

type AffectedDBBellSoftHardenedContainers struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBBellSoftHardenedContainers) IsZero() bool {
	return a == AffectedDBBellSoftHardenedContainers{}
}

func NewRecordBellSoftHardenedContainers(r io.Reader) (*RecordBellSoftHardenedContainers, error) {
	var rec RecordBellSoftHardenedContainers
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse BellSoftHardenedContainers: %w", err)
	}
	rec.Ecosystem = EcosystemBellSoftHardenedContainers
	return &rec, nil
}

// ============================================================
// CRAN
// ============================================================

type RecordCRAN struct {
	Record
	Affected         []AffectedCRAN `json:"affected,omitempty"`
	DatabaseSpecific TopCRAN        `json:"database_specific,omitzero"`
}

func (r *RecordCRAN) Base() *Record      { return &r.Record }
func (r *RecordCRAN) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedCRAN struct {
	AffectedBase
	Ranges            []RangeCRAN     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoCRAN `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBCRAN  `json:"database_specific,omitzero"`
}

type RangeCRAN struct{ RangeBase }

type TopCRAN struct{}

func (TopCRAN) IsZero() bool { return true }

type AffectedEcoCRAN struct{}

func (AffectedEcoCRAN) IsZero() bool { return true }

type AffectedDBCRAN struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBCRAN) IsZero() bool { return a == AffectedDBCRAN{} }

func NewRecordCRAN(r io.Reader) (*RecordCRAN, error) {
	var rec RecordCRAN
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse CRAN: %w", err)
	}
	rec.Ecosystem = EcosystemCRAN
	return &rec, nil
}

// ============================================================
// CleanStart
// ============================================================

type RecordCleanStart struct {
	Record
	Affected         []AffectedCleanStart `json:"affected,omitempty"`
	DatabaseSpecific TopCleanStart        `json:"database_specific,omitzero"`
}

func (r *RecordCleanStart) Base() *Record      { return &r.Record }
func (r *RecordCleanStart) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedCleanStart struct {
	AffectedBase
	Ranges            []RangeCleanStart     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoCleanStart `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBCleanStart  `json:"database_specific,omitzero"`
}

type RangeCleanStart struct{ RangeBase }

type TopCleanStart struct{}

func (TopCleanStart) IsZero() bool { return true }

type AffectedEcoCleanStart struct{}

func (AffectedEcoCleanStart) IsZero() bool { return true }

type AffectedDBCleanStart struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBCleanStart) IsZero() bool { return a == AffectedDBCleanStart{} }

func NewRecordCleanStart(r io.Reader) (*RecordCleanStart, error) {
	var rec RecordCleanStart
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse CleanStart: %w", err)
	}
	rec.Ecosystem = EcosystemCleanStart
	return &rec, nil
}

// ============================================================
// Echo
// ============================================================

type RecordEcho struct {
	Record
	Affected         []AffectedEcho `json:"affected,omitempty"`
	DatabaseSpecific TopEcho        `json:"database_specific,omitzero"`
}

func (r *RecordEcho) Base() *Record      { return &r.Record }
func (r *RecordEcho) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedEcho struct {
	AffectedBase
	Ranges            []RangeEcho     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoEcho `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBEcho  `json:"database_specific,omitzero"`
}

type RangeEcho struct{ RangeBase }

type TopEcho struct{}

func (TopEcho) IsZero() bool { return true }

type AffectedEcoEcho struct{}

func (AffectedEcoEcho) IsZero() bool { return true }

type AffectedDBEcho struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBEcho) IsZero() bool { return a == AffectedDBEcho{} }

func NewRecordEcho(r io.Reader) (*RecordEcho, error) {
	var rec RecordEcho
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse Echo: %w", err)
	}
	rec.Ecosystem = EcosystemEcho
	return &rec, nil
}

// ============================================================
// GSD
// ============================================================

type RecordGSD struct {
	Record
	Affected         []AffectedGSD `json:"affected,omitempty"`
	DatabaseSpecific TopGSD        `json:"database_specific,omitzero"`
}

func (r *RecordGSD) Base() *Record      { return &r.Record }
func (r *RecordGSD) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedGSD struct {
	AffectedBase
	Ranges            []RangeGSD     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGSD `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGSD  `json:"database_specific,omitzero"`
}

type RangeGSD struct{ RangeBase }

type TopGSD struct{}

func (TopGSD) IsZero() bool { return true }

type AffectedEcoGSD struct{}

func (AffectedEcoGSD) IsZero() bool { return true }

type AffectedDBGSD struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBGSD) IsZero() bool { return a == AffectedDBGSD{} }

func NewRecordGSD(r io.Reader) (*RecordGSD, error) {
	var rec RecordGSD
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse GSD: %w", err)
	}
	rec.Ecosystem = EcosystemGSD
	return &rec, nil
}

// ============================================================
// Red Hat
// ============================================================

type RecordRedHat struct {
	Record
	Affected         []AffectedRedHat `json:"affected,omitempty"`
	DatabaseSpecific TopRedHat        `json:"database_specific,omitzero"`
}

func (r *RecordRedHat) Base() *Record      { return &r.Record }
func (r *RecordRedHat) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedRedHat struct {
	AffectedBase
	Ranges            []RangeRedHat     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRedHat `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRedHat  `json:"database_specific,omitzero"`
}

type RangeRedHat struct{ RangeBase }

type TopRedHat struct{}

func (TopRedHat) IsZero() bool { return true }

type AffectedEcoRedHat struct{}

func (AffectedEcoRedHat) IsZero() bool { return true }

type AffectedDBRedHat struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBRedHat) IsZero() bool { return a == AffectedDBRedHat{} }

func NewRecordRedHat(r io.Reader) (*RecordRedHat, error) {
	var rec RecordRedHat
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse RedHat: %w", err)
	}
	rec.Ecosystem = EcosystemRedHat
	return &rec, nil
}

// ============================================================
// UVI
// ============================================================

type RecordUVI struct {
	Record
	Affected         []AffectedUVI `json:"affected,omitempty"`
	DatabaseSpecific TopUVI        `json:"database_specific,omitzero"`
}

func (r *RecordUVI) Base() *Record      { return &r.Record }
func (r *RecordUVI) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedUVI struct {
	AffectedBase
	Ranges            []RangeUVI     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoUVI `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBUVI  `json:"database_specific,omitzero"`
}

type RangeUVI struct{ RangeBase }

type TopUVI struct{}

func (TopUVI) IsZero() bool { return true }

type AffectedEcoUVI struct{}

func (AffectedEcoUVI) IsZero() bool { return true }

type AffectedDBUVI struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBUVI) IsZero() bool { return a == AffectedDBUVI{} }

func NewRecordUVI(r io.Reader) (*RecordUVI, error) {
	var rec RecordUVI
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse UVI: %w", err)
	}
	rec.Ecosystem = EcosystemUVI
	return &rec, nil
}
