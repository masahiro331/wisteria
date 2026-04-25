package epss

import (
	"strings"
	"testing"
)

func TestRead_HappyPath(t *testing.T) {
	const body = `#model_version:v2025.03.14,score_date:2026-04-24T12:55:00Z
cve,epss,percentile
CVE-1999-0001,0.0119,0.78874
CVE-1999-0002,0.10103,0.9312
CVE-2021-44228,0.94358,0.99962
`
	got, err := Read(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Scores) != 3 {
		t.Fatalf("len(Scores) = %d, want 3", len(got.Scores))
	}
	want := Score{CVE: "CVE-2021-44228", EPSS: 0.94358, Percentile: 0.99962}
	if got.Scores[2] != want {
		t.Errorf("Scores[2] = %#v, want %#v", got.Scores[2], want)
	}
	// The leading `#model_version:..,score_date:..` comment carries the
	// catalog metadata Stage 4 attaches to each score; the parser must
	// expose it instead of dropping it on the floor.
	if got.ModelVersion != "v2025.03.14" {
		t.Errorf("ModelVersion = %q, want v2025.03.14", got.ModelVersion)
	}
	if got.ScoreDate != "2026-04-24T12:55:00Z" {
		t.Errorf("ScoreDate = %q, want 2026-04-24T12:55:00Z", got.ScoreDate)
	}
}

func TestRead_HeaderCommentMissingFieldsLeavesEmpty(t *testing.T) {
	// A non-conforming comment line (no model_version / score_date) must
	// not error — Stage 4 falls back to attaching just the score.
	const body = `#unrelated comment
cve,epss,percentile
CVE-2024-0001,0.5,0.9
`
	got, err := Read(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.ModelVersion != "" || got.ScoreDate != "" {
		t.Errorf("expected empty metadata, got ModelVersion=%q ScoreDate=%q",
			got.ModelVersion, got.ScoreDate)
	}
}

func TestRead_SkipsCommentAndHeader(t *testing.T) {
	// The catalog always begins with a # comment line and a CSV header line.
	// Both must be skipped without ending up in Scores.
	const body = `#anything,goes,here
cve,epss,percentile
CVE-2024-0001,0.5,0.9
`
	got, err := Read(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Scores) != 1 {
		t.Fatalf("len(Scores) = %d, want 1", len(got.Scores))
	}
	if got.Scores[0].CVE != "CVE-2024-0001" {
		t.Errorf("CVE = %q", got.Scores[0].CVE)
	}
}

func TestRead_RejectsMalformedScore(t *testing.T) {
	const body = `#h
cve,epss,percentile
CVE-1,not-a-float,0.5
`
	if _, err := Read(strings.NewReader(body)); err == nil {
		t.Fatal("expected error for non-float score, got nil")
	}
}

func TestRead_RejectsRowWithMissingColumns(t *testing.T) {
	const body = `#h
cve,epss,percentile
CVE-1,0.5
`
	if _, err := Read(strings.NewReader(body)); err == nil {
		t.Fatal("expected error for short row, got nil")
	}
}

func TestRead_EmptyAfterHeaderIsOK(t *testing.T) {
	const body = `#h
cve,epss,percentile
`
	got, err := Read(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(got.Scores))
	}
}
