package unifier

// sourcePriority is the draft cross-field vendor ordering from §8.1. The
// final membership and order is decided in #22 once `wisteria debug
// fields` has been run against real data; until then, sources missing
// from this list fall through to defaultRank (sorted last).
//
// Tag format: "<SourceKind>.<ecosystem>". CVE5 is a single fixed tag
// "cve.mitre" because every CVE5 file is treated as the CNA-of-record.
var sourcePriority = []string{
	"cve.mitre",
	"osv.RedHat",
	"osv.AlmaLinux",
	"osv.Rocky Linux",
	"osv.SUSE",
	"osv.Ubuntu",
	"osv.Debian",
	"osv.Alpine",
	"osv.GitHub Reviewed",
	"osv.PyPI",
	"osv.npm",
	"osv.Go",
}

// priorityRank returns the position of source in sourcePriority. Sources
// not in the list rank after every listed source (len(sourcePriority)),
// which keeps unranked entries at the tail without sentinel constants.
// Lower is higher priority.
func priorityRank(source string) int {
	for i, s := range sourcePriority {
		if s == source {
			return i
		}
	}
	return len(sourcePriority)
}
