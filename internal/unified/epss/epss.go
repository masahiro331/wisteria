// Package epss defines parser types for the FIRST EPSS daily score CSV.
// The leading "#model_version:..,score_date:.." comment carries catalog
// metadata that Stage 4 attaches to each score; per-CVE rows make up the
// rest of the file.
package epss

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Catalog holds every score row from one EPSS CSV file plus the
// model_version / score_date pair from the leading "#..." comment.
type Catalog struct {
	ModelVersion string
	ScoreDate    string
	Scores       []Score
}

// Score is one CSV row.
type Score struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// Read parses the EPSS CSV stream. The first line is expected to be a
// "#model_version:<v>,score_date:<ts>" comment (other shapes leave the
// metadata empty without erroring) and the second line the CSV header
// (`cve,epss,percentile`); both are consumed before the row loop.
// Remaining rows must have exactly three columns.
func Read(r io.Reader) (Catalog, error) {
	br := bufio.NewReader(r)
	var out Catalog

	// Peek the first line: if it starts with '#', treat it as the metadata
	// comment and consume it; otherwise leave it for csv.Reader (handles
	// streams that don't have a comment line — e.g. trimmed test inputs).
	first, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return Catalog{}, fmt.Errorf("epss header: %w", err)
	}
	if strings.HasPrefix(first, "#") {
		out.ModelVersion, out.ScoreDate = parseHeaderComment(first)
	} else if first != "" {
		// No comment line — push the line back by chaining a multi-reader.
		r = io.MultiReader(strings.NewReader(first), br)
		br = bufio.NewReader(r)
	}

	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3

	// Drop the header row.
	if _, err := cr.Read(); err != nil {
		if err == io.EOF {
			return out, nil
		}
		return Catalog{}, fmt.Errorf("epss header: %w", err)
	}

	line := 2 // metadata comment + header consumed; data rows start at logical line 3
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

// parseHeaderComment extracts model_version and score_date from a
// "#k1:v1,k2:v2,..." line. Unknown keys are ignored; missing keys leave
// the corresponding field empty so a future schema change doesn't break
// parsing — Stage 4 just falls back to attaching the score alone.
func parseHeaderComment(line string) (modelVersion, scoreDate string) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	for kv := range strings.SplitSeq(line, ",") {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model_version":
			modelVersion = strings.TrimSpace(v)
		case "score_date":
			scoreDate = strings.TrimSpace(v)
		}
	}
	return modelVersion, scoreDate
}
