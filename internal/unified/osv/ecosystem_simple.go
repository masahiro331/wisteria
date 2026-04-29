package osv

// This file groups ecosystems whose `database_specific` /
// `ecosystem_specific` payloads are trivial — typically a single
// `source` URL on each affected entry and nothing else. Each ecosystem
// still gets its own concrete types per the design's strict-dispatch
// rule; sharing across ecosystems is intentionally avoided so a
// future divergence (say AlmaLinux 9 ships extra metadata) does not
// silently grow the shared struct under everyone else's feet.
//
// Inventory source: tools/osv-inventory full-corpus run (see
// docs/ROADMAP.md / issue #69).

// --- Source-only ecosystems --------------------------------------
// affected[].database_specific = {"source": "..."}; everything else
// empty. One pair of structs per ecosystem.

// AlmaLinux

type TopAlmaLinux struct{}

func (*TopAlmaLinux) isTopSpecific() {}

type AffectedEcoAlmaLinux struct{}

func (*AffectedEcoAlmaLinux) isAffectedEcoSpec() {}

type AffectedDBAlmaLinux struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBAlmaLinux) isAffectedDBSpec() {}

type RangeDBAlmaLinux struct{}

func (*RangeDBAlmaLinux) isRangeDBSpec() {}

// Alpaquita

type TopAlpaquita struct{}

func (*TopAlpaquita) isTopSpecific() {}

type AffectedEcoAlpaquita struct{}

func (*AffectedEcoAlpaquita) isAffectedEcoSpec() {}

type AffectedDBAlpaquita struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBAlpaquita) isAffectedDBSpec() {}

type RangeDBAlpaquita struct{}

func (*RangeDBAlpaquita) isRangeDBSpec() {}

// Alpine

type TopAlpine struct{}

func (*TopAlpine) isTopSpecific() {}

type AffectedEcoAlpine struct{}

func (*AffectedEcoAlpine) isAffectedEcoSpec() {}

type AffectedDBAlpine struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBAlpine) isAffectedDBSpec() {}

type RangeDBAlpine struct{}

func (*RangeDBAlpine) isRangeDBSpec() {}

// Azure Linux

type TopAzureLinux struct{}

func (*TopAzureLinux) isTopSpecific() {}

type AffectedEcoAzureLinux struct{}

func (*AffectedEcoAzureLinux) isAffectedEcoSpec() {}

type AffectedDBAzureLinux struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBAzureLinux) isAffectedDBSpec() {}

type RangeDBAzureLinux struct{}

func (*RangeDBAzureLinux) isRangeDBSpec() {}

// BellSoft Hardened Containers

type TopBellSoftHardenedContainers struct{}

func (*TopBellSoftHardenedContainers) isTopSpecific() {}

type AffectedEcoBellSoftHardenedContainers struct{}

func (*AffectedEcoBellSoftHardenedContainers) isAffectedEcoSpec() {}

type AffectedDBBellSoftHardenedContainers struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBBellSoftHardenedContainers) isAffectedDBSpec() {}

type RangeDBBellSoftHardenedContainers struct{}

func (*RangeDBBellSoftHardenedContainers) isRangeDBSpec() {}

// CRAN

type TopCRAN struct{}

func (*TopCRAN) isTopSpecific() {}

type AffectedEcoCRAN struct{}

func (*AffectedEcoCRAN) isAffectedEcoSpec() {}

type AffectedDBCRAN struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBCRAN) isAffectedDBSpec() {}

type RangeDBCRAN struct{}

func (*RangeDBCRAN) isRangeDBSpec() {}

// CleanStart

type TopCleanStart struct{}

func (*TopCleanStart) isTopSpecific() {}

type AffectedEcoCleanStart struct{}

func (*AffectedEcoCleanStart) isAffectedEcoSpec() {}

type AffectedDBCleanStart struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBCleanStart) isAffectedDBSpec() {}

type RangeDBCleanStart struct{}

func (*RangeDBCleanStart) isRangeDBSpec() {}

// Echo

type TopEcho struct{}

func (*TopEcho) isTopSpecific() {}

type AffectedEcoEcho struct{}

func (*AffectedEcoEcho) isAffectedEcoSpec() {}

type AffectedDBEcho struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBEcho) isAffectedDBSpec() {}

type RangeDBEcho struct{}

func (*RangeDBEcho) isRangeDBSpec() {}

// GSD

type TopGSD struct{}

func (*TopGSD) isTopSpecific() {}

type AffectedEcoGSD struct{}

func (*AffectedEcoGSD) isAffectedEcoSpec() {}

type AffectedDBGSD struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBGSD) isAffectedDBSpec() {}

type RangeDBGSD struct{}

func (*RangeDBGSD) isRangeDBSpec() {}

// Red Hat

type TopRedHat struct{}

func (*TopRedHat) isTopSpecific() {}

type AffectedEcoRedHat struct{}

func (*AffectedEcoRedHat) isAffectedEcoSpec() {}

type AffectedDBRedHat struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBRedHat) isAffectedDBSpec() {}

type RangeDBRedHat struct{}

func (*RangeDBRedHat) isRangeDBSpec() {}

// Rocky Linux

type TopRockyLinux struct{}

func (*TopRockyLinux) isTopSpecific() {}

type AffectedEcoRockyLinux struct{}

func (*AffectedEcoRockyLinux) isAffectedEcoSpec() {}

type AffectedDBRockyLinux struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBRockyLinux) isAffectedDBSpec() {}

// RangeDBRockyLinux captures range-level `database_specific` for
// Rocky Linux: `yum_repository` (e.g. "CRB", "AppStream") appears on
// a subset of advisories.
type RangeDBRockyLinux struct {
	YumRepository string `json:"yum_repository,omitempty"`
}

func (*RangeDBRockyLinux) isRangeDBSpec() {}

// UVI

type TopUVI struct{}

func (*TopUVI) isTopSpecific() {}

type AffectedEcoUVI struct{}

func (*AffectedEcoUVI) isAffectedEcoSpec() {}

type AffectedDBUVI struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBUVI) isAffectedDBSpec() {}

type RangeDBUVI struct{}

func (*RangeDBUVI) isRangeDBSpec() {}

// --- Source + range false_positive group -------------------------

// Chainguard

type TopChainguard struct{}

func (*TopChainguard) isTopSpecific() {}

type AffectedEcoChainguard struct{}

func (*AffectedEcoChainguard) isAffectedEcoSpec() {}

type AffectedDBChainguard struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBChainguard) isAffectedDBSpec() {}

type RangeDBChainguard struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (*RangeDBChainguard) isRangeDBSpec() {}

// Wolfi

type TopWolfi struct{}

func (*TopWolfi) isTopSpecific() {}

type AffectedEcoWolfi struct{}

func (*AffectedEcoWolfi) isAffectedEcoSpec() {}

type AffectedDBWolfi struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBWolfi) isAffectedDBSpec() {}

type RangeDBWolfi struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (*RangeDBWolfi) isRangeDBSpec() {}

// MinimOS

type TopMinimOS struct{}

func (*TopMinimOS) isTopSpecific() {}

type AffectedEcoMinimOS struct{}

func (*AffectedEcoMinimOS) isAffectedEcoSpec() {}

type AffectedDBMinimOS struct {
	Source string `json:"source,omitempty"`
}

func (*AffectedDBMinimOS) isAffectedDBSpec() {}

type RangeDBMinimOS struct {
	FalsePositive bool `json:"false_positive,omitempty"`
}

func (*RangeDBMinimOS) isRangeDBSpec() {}

func init() {
	register("AlmaLinux", ecosystemDispatch{
		top:    func() TopSpecific { return &TopAlmaLinux{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoAlmaLinux{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBAlmaLinux{} },
		rngDB:  func() RangeDBSpec { return &RangeDBAlmaLinux{} },
	})
	register("Alpaquita", ecosystemDispatch{
		top:    func() TopSpecific { return &TopAlpaquita{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoAlpaquita{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBAlpaquita{} },
		rngDB:  func() RangeDBSpec { return &RangeDBAlpaquita{} },
	})
	register("Alpine", ecosystemDispatch{
		top:    func() TopSpecific { return &TopAlpine{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoAlpine{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBAlpine{} },
		rngDB:  func() RangeDBSpec { return &RangeDBAlpine{} },
	})
	register("Azure Linux", ecosystemDispatch{
		top:    func() TopSpecific { return &TopAzureLinux{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoAzureLinux{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBAzureLinux{} },
		rngDB:  func() RangeDBSpec { return &RangeDBAzureLinux{} },
	})
	register("BellSoft Hardened Containers", ecosystemDispatch{
		top:    func() TopSpecific { return &TopBellSoftHardenedContainers{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoBellSoftHardenedContainers{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBBellSoftHardenedContainers{} },
		rngDB:  func() RangeDBSpec { return &RangeDBBellSoftHardenedContainers{} },
	})
	register("CRAN", ecosystemDispatch{
		top:    func() TopSpecific { return &TopCRAN{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoCRAN{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBCRAN{} },
		rngDB:  func() RangeDBSpec { return &RangeDBCRAN{} },
	})
	register("CleanStart", ecosystemDispatch{
		top:    func() TopSpecific { return &TopCleanStart{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoCleanStart{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBCleanStart{} },
		rngDB:  func() RangeDBSpec { return &RangeDBCleanStart{} },
	})
	register("Echo", ecosystemDispatch{
		top:    func() TopSpecific { return &TopEcho{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoEcho{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBEcho{} },
		rngDB:  func() RangeDBSpec { return &RangeDBEcho{} },
	})
	register("GSD", ecosystemDispatch{
		top:    func() TopSpecific { return &TopGSD{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoGSD{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBGSD{} },
		rngDB:  func() RangeDBSpec { return &RangeDBGSD{} },
	})
	register("Red Hat", ecosystemDispatch{
		top:    func() TopSpecific { return &TopRedHat{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoRedHat{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBRedHat{} },
		rngDB:  func() RangeDBSpec { return &RangeDBRedHat{} },
	})
	register("Rocky Linux", ecosystemDispatch{
		top:    func() TopSpecific { return &TopRockyLinux{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoRockyLinux{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBRockyLinux{} },
		rngDB:  func() RangeDBSpec { return &RangeDBRockyLinux{} },
	})
	register("UVI", ecosystemDispatch{
		top:    func() TopSpecific { return &TopUVI{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoUVI{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBUVI{} },
		rngDB:  func() RangeDBSpec { return &RangeDBUVI{} },
	})
	register("Chainguard", ecosystemDispatch{
		top:    func() TopSpecific { return &TopChainguard{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoChainguard{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBChainguard{} },
		rngDB:  func() RangeDBSpec { return &RangeDBChainguard{} },
	})
	register("Wolfi", ecosystemDispatch{
		top:    func() TopSpecific { return &TopWolfi{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoWolfi{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBWolfi{} },
		rngDB:  func() RangeDBSpec { return &RangeDBWolfi{} },
	})
	register("MinimOS", ecosystemDispatch{
		top:    func() TopSpecific { return &TopMinimOS{} },
		affEco: func() AffectedEcoSpec { return &AffectedEcoMinimOS{} },
		affDB:  func() AffectedDBSpec { return &AffectedDBMinimOS{} },
		rngDB:  func() RangeDBSpec { return &RangeDBMinimOS{} },
	})
}
