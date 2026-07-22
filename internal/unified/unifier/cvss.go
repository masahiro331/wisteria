package unifier

import (
	"strconv"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// baseScoreFromVector computes the CVSS base score for a vector string,
// dispatching on the version header (CVSS v2 vectors ship headerless as
// "AV:.../..."). It returns "" for anything that is not a parseable
// CVSS vector — non-CVSS rating words ("medium") and malformed vectors
// are left for the caller to keep verbatim, never an error: a bad
// vector from one source must not abort the merge of a whole record.
func baseScoreFromVector(vector string) string {
	var (
		score float64
		err   error
	)
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		var v *gocvss40.CVSS40
		if v, err = gocvss40.ParseVector(vector); err == nil {
			score = v.Score()
		}
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		var v *gocvss31.CVSS31
		if v, err = gocvss31.ParseVector(vector); err == nil {
			score = v.BaseScore()
		}
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		var v *gocvss30.CVSS30
		if v, err = gocvss30.ParseVector(vector); err == nil {
			score = v.BaseScore()
		}
	case strings.HasPrefix(vector, "AV:"):
		var v *gocvss20.CVSS20
		if v, err = gocvss20.ParseVector(vector); err == nil {
			score = v.BaseScore()
		}
	default:
		return ""
	}
	if err != nil {
		return ""
	}
	return strconv.FormatFloat(score, 'f', -1, 64)
}
