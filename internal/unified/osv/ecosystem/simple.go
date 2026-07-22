package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/masahiro331/wisteria/internal/unified/osv"
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
	osv.Record
	Affected         []AffectedAlmaLinux `json:"affected,omitempty"`
	DatabaseSpecific TopAlmaLinux        `json:"database_specific,omitzero"`
}

func (r *RecordAlmaLinux) Base() *osv.Record  { return &r.Record }
func (r *RecordAlmaLinux) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordAlmaLinux) CWEIDs() []string   { return nil }

type AffectedAlmaLinux struct {
	osv.AffectedBase
	Ranges            []RangeAlmaLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlmaLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlmaLinux  `json:"database_specific,omitzero"`
}

type RangeAlmaLinux struct {
	osv.RangeBase
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
	rec.Ecosystem = osv.EcosystemAlmaLinux
	return &rec, nil
}

// ============================================================
// Alpaquita
// ============================================================

type RecordAlpaquita struct {
	osv.Record
	Affected         []AffectedAlpaquita `json:"affected,omitempty"`
	DatabaseSpecific TopAlpaquita        `json:"database_specific,omitzero"`
}

func (r *RecordAlpaquita) Base() *osv.Record  { return &r.Record }
func (r *RecordAlpaquita) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordAlpaquita) CWEIDs() []string   { return nil }

type AffectedAlpaquita struct {
	osv.AffectedBase
	Ranges            []RangeAlpaquita     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlpaquita `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlpaquita  `json:"database_specific,omitzero"`
}

type RangeAlpaquita struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemAlpaquita
	return &rec, nil
}

// ============================================================
// Alpine
// ============================================================

type RecordAlpine struct {
	osv.Record
	Affected         []AffectedAlpine `json:"affected,omitempty"`
	DatabaseSpecific TopAlpine        `json:"database_specific,omitzero"`
}

func (r *RecordAlpine) Base() *osv.Record  { return &r.Record }
func (r *RecordAlpine) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordAlpine) CWEIDs() []string   { return nil }

type AffectedAlpine struct {
	osv.AffectedBase
	Ranges            []RangeAlpine     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAlpine `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAlpine  `json:"database_specific,omitzero"`
}

type RangeAlpine struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemAlpine
	return &rec, nil
}

// ============================================================
// Azure Linux
// ============================================================

type RecordAzureLinux struct {
	osv.Record
	Affected         []AffectedAzureLinux `json:"affected,omitempty"`
	DatabaseSpecific TopAzureLinux        `json:"database_specific,omitzero"`
}

func (r *RecordAzureLinux) Base() *osv.Record  { return &r.Record }
func (r *RecordAzureLinux) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordAzureLinux) CWEIDs() []string   { return nil }

type AffectedAzureLinux struct {
	osv.AffectedBase
	Ranges            []RangeAzureLinux     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoAzureLinux `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBAzureLinux  `json:"database_specific,omitzero"`
}

type RangeAzureLinux struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemAzureLinux
	return &rec, nil
}

// ============================================================
// BellSoft Hardened Containers
// ============================================================

type RecordBellSoftHardenedContainers struct {
	osv.Record
	Affected         []AffectedBellSoftHardenedContainers `json:"affected,omitempty"`
	DatabaseSpecific TopBellSoftHardenedContainers        `json:"database_specific,omitzero"`
}

func (r *RecordBellSoftHardenedContainers) Base() *osv.Record  { return &r.Record }
func (r *RecordBellSoftHardenedContainers) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordBellSoftHardenedContainers) CWEIDs() []string   { return nil }

type AffectedBellSoftHardenedContainers struct {
	osv.AffectedBase
	Ranges            []RangeBellSoftHardenedContainers     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoBellSoftHardenedContainers `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBBellSoftHardenedContainers  `json:"database_specific,omitzero"`
}

type RangeBellSoftHardenedContainers struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemBellSoftHardenedContainers
	return &rec, nil
}

// ============================================================
// CRAN
// ============================================================

type RecordCRAN struct {
	osv.Record
	Affected         []AffectedCRAN `json:"affected,omitempty"`
	DatabaseSpecific TopCRAN        `json:"database_specific,omitzero"`
}

func (r *RecordCRAN) Base() *osv.Record  { return &r.Record }
func (r *RecordCRAN) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordCRAN) CWEIDs() []string   { return nil }

type AffectedCRAN struct {
	osv.AffectedBase
	Ranges            []RangeCRAN     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoCRAN `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBCRAN  `json:"database_specific,omitzero"`
}

type RangeCRAN struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemCRAN
	return &rec, nil
}

// ============================================================
// CleanStart
// ============================================================

type RecordCleanStart struct {
	osv.Record
	Affected         []AffectedCleanStart `json:"affected,omitempty"`
	DatabaseSpecific TopCleanStart        `json:"database_specific,omitzero"`
}

func (r *RecordCleanStart) Base() *osv.Record  { return &r.Record }
func (r *RecordCleanStart) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordCleanStart) CWEIDs() []string   { return nil }

type AffectedCleanStart struct {
	osv.AffectedBase
	Ranges            []RangeCleanStart     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoCleanStart `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBCleanStart  `json:"database_specific,omitzero"`
}

type RangeCleanStart struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemCleanStart
	return &rec, nil
}

// ============================================================
// Echo
// ============================================================

type RecordEcho struct {
	osv.Record
	Affected         []AffectedEcho `json:"affected,omitempty"`
	DatabaseSpecific TopEcho        `json:"database_specific,omitzero"`
}

func (r *RecordEcho) Base() *osv.Record  { return &r.Record }
func (r *RecordEcho) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordEcho) CWEIDs() []string   { return nil }

type AffectedEcho struct {
	osv.AffectedBase
	Ranges            []RangeEcho     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoEcho `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBEcho  `json:"database_specific,omitzero"`
}

type RangeEcho struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemEcho
	return &rec, nil
}

// ============================================================
// GSD
// ============================================================

type RecordGSD struct {
	osv.Record
	Affected         []AffectedGSD `json:"affected,omitempty"`
	DatabaseSpecific TopGSD        `json:"database_specific,omitzero"`
}

func (r *RecordGSD) Base() *osv.Record  { return &r.Record }
func (r *RecordGSD) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordGSD) CWEIDs() []string   { return nil }

type AffectedGSD struct {
	osv.AffectedBase
	Ranges            []RangeGSD     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoGSD `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBGSD  `json:"database_specific,omitzero"`
}

type RangeGSD struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemGSD
	return &rec, nil
}

// ============================================================
// Red Hat
// ============================================================

type RecordRedHat struct {
	osv.Record
	Affected         []AffectedRedHat `json:"affected,omitempty"`
	DatabaseSpecific TopRedHat        `json:"database_specific,omitzero"`
}

func (r *RecordRedHat) Base() *osv.Record  { return &r.Record }
func (r *RecordRedHat) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordRedHat) CWEIDs() []string   { return nil }

type AffectedRedHat struct {
	osv.AffectedBase
	Ranges            []RangeRedHat     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoRedHat `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBRedHat  `json:"database_specific,omitzero"`
}

type RangeRedHat struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemRedHat
	return &rec, nil
}

// ============================================================
// UVI
// ============================================================

type RecordUVI struct {
	osv.Record
	Affected         []AffectedUVI `json:"affected,omitempty"`
	DatabaseSpecific TopUVI        `json:"database_specific,omitzero"`
}

func (r *RecordUVI) Base() *osv.Record  { return &r.Record }
func (r *RecordUVI) AffectedAny() []any { return affectedAny(r.Affected) }
func (r *RecordUVI) CWEIDs() []string   { return nil }

type AffectedUVI struct {
	osv.AffectedBase
	Ranges            []RangeUVI     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoUVI `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBUVI  `json:"database_specific,omitzero"`
}

type RangeUVI struct{ osv.RangeBase }

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
	rec.Ecosystem = osv.EcosystemUVI
	return &rec, nil
}

// ============================================================
// TuxCare
// ============================================================

type RecordTuxCare struct {
	osv.Record
	Affected         []AffectedTuxCare `json:"affected,omitempty"`
	DatabaseSpecific TopTuxCare        `json:"database_specific,omitzero"`
}

func (r *RecordTuxCare) Base() *osv.Record  { return &r.Record }
func (r *RecordTuxCare) AffectedAny() []any { return affectedAny(r.Affected) }

type AffectedTuxCare struct {
	osv.AffectedBase
	Ranges            []RangeTuxCare     `json:"ranges,omitempty"`
	EcosystemSpecific AffectedEcoTuxCare `json:"ecosystem_specific,omitzero"`
	DatabaseSpecific  AffectedDBTuxCare  `json:"database_specific,omitzero"`
}

type RangeTuxCare struct {
	osv.RangeBase
}

type TopTuxCare struct{}

func (TopTuxCare) IsZero() bool { return true }

type AffectedEcoTuxCare struct{}

func (AffectedEcoTuxCare) IsZero() bool { return true }

// AffectedDBTuxCare carries the per-package pointer back to the
// cloudlinux/tuxcare-osv source file.
type AffectedDBTuxCare struct {
	Source string `json:"source,omitempty"`
}

func (a AffectedDBTuxCare) IsZero() bool { return a == AffectedDBTuxCare{} }

func NewRecordTuxCare(r io.Reader) (*RecordTuxCare, error) {
	var rec RecordTuxCare
	if err := json.NewDecoder(r).Decode(&rec); err != nil {
		return nil, fmt.Errorf("osv: parse TuxCare: %w", err)
	}
	rec.Ecosystem = osv.EcosystemTuxCare
	return &rec, nil
}
