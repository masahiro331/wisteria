// Package epss defines parser types for the FIRST EPSS daily score CSV.
// The leading "#model_version:..,score_date:..." comment is intentionally
// ignored; downstream stages read only per-CVE scores.
package epss

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

// Catalog holds every score row from one EPSS CSV file.
type Catalog struct {
	Scores []Score
}

// Score is one CSV row.
type Score struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// Read parses the EPSS CSV stream. The first line is expected to be a
// "#..." comment and the second line the CSV header (`cve,epss,percentile`);
// both are skipped. Remaining rows must have exactly three columns.
func Read(r io.Reader) (Catalog, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.FieldsPerRecord = 3

	// Drop the header row.
	if _, err := cr.Read(); err != nil {
		if err == io.EOF {
			return Catalog{}, nil
		}
		return Catalog{}, fmt.Errorf("epss header: %w", err)
	}

	var out Catalog
	line := 2 // header consumed; data rows start at logical line 3
	for {
		line++
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Catalog{}, fmt.Errorf("epss row %d: %w", line, err)
		}
		score, err := strconv.ParseFloat(row[1], 64)
		if err != nil {
			return Catalog{}, fmt.Errorf("epss row %d: parse epss: %w", line, err)
		}
		percentile, err := strconv.ParseFloat(row[2], 64)
		if err != nil {
			return Catalog{}, fmt.Errorf("epss row %d: parse percentile: %w", line, err)
		}
		out.Scores = append(out.Scores, Score{
			CVE:        row[0],
			EPSS:       score,
			Percentile: percentile,
		})
	}
	return out, nil
}
