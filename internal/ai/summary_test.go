package ai_test

import (
	"strings"
	"testing"

	"github.com/masahiro331/wisteria/internal/ai"
)

func TestAdvisoryAISummary_Validate_AcceptsValidConfidence(t *testing.T) {
	t.Parallel()
	for _, c := range []float64{0, 0.5, 1} {
		s := ai.AdvisoryAISummary{Title: "x", Confidence: c}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(confidence=%v) returned %v, want nil", c, err)
		}
	}
}

func TestAdvisoryAISummary_Validate_RejectsOutOfRangeConfidence(t *testing.T) {
	t.Parallel()
	for _, c := range []float64{-0.01, 1.01, 2, -1} {
		s := ai.AdvisoryAISummary{Title: "x", Confidence: c}
		err := s.Validate()
		if err == nil {
			t.Errorf("Validate(confidence=%v) returned nil, want error", c)
			continue
		}
		if !strings.Contains(err.Error(), "confidence") {
			t.Errorf("Validate(confidence=%v) error = %v, want it to mention confidence", c, err)
		}
	}
}

func TestAdvisoryAISummary_Validate_RejectsEmptyTitle(t *testing.T) {
	t.Parallel()
	s := ai.AdvisoryAISummary{Title: "", Confidence: 0.5}
	err := s.Validate()
	if err == nil {
		t.Fatal("Validate(title=\"\") returned nil, want error")
	}
	if !strings.Contains(err.Error(), "title") {
		t.Errorf("error = %v, want it to mention title", err)
	}
}

func TestAdvisoryAISummary_Normalize_ReplacesNilArraysWithEmpty(t *testing.T) {
	t.Parallel()
	s := ai.AdvisoryAISummary{
		AffectedProducts:   nil,
		AffectedVersions:   nil,
		FixedVersions:      nil,
		MissingInformation: nil,
	}
	s.Normalize()
	if s.AffectedProducts == nil {
		t.Error("AffectedProducts is still nil after Normalize")
	}
	if s.AffectedVersions == nil {
		t.Error("AffectedVersions is still nil after Normalize")
	}
	if s.FixedVersions == nil {
		t.Error("FixedVersions is still nil after Normalize")
	}
	if s.MissingInformation == nil {
		t.Error("MissingInformation is still nil after Normalize")
	}
	for _, arr := range [][]string{s.AffectedProducts, s.AffectedVersions, s.FixedVersions, s.MissingInformation} {
		if len(arr) != 0 {
			t.Errorf("normalized array should be empty, got %v", arr)
		}
	}
}

func TestAdvisoryAISummary_Normalize_PreservesExistingValues(t *testing.T) {
	t.Parallel()
	s := ai.AdvisoryAISummary{
		AffectedProducts:   []string{"libfoo"},
		AffectedVersions:   []string{"<1.2"},
		FixedVersions:      []string{"1.2"},
		MissingInformation: []string{"patch_url"},
	}
	s.Normalize()
	if got := s.AffectedProducts; len(got) != 1 || got[0] != "libfoo" {
		t.Errorf("AffectedProducts mutated: %v", got)
	}
	if got := s.AffectedVersions; len(got) != 1 || got[0] != "<1.2" {
		t.Errorf("AffectedVersions mutated: %v", got)
	}
	if got := s.FixedVersions; len(got) != 1 || got[0] != "1.2" {
		t.Errorf("FixedVersions mutated: %v", got)
	}
	if got := s.MissingInformation; len(got) != 1 || got[0] != "patch_url" {
		t.Errorf("MissingInformation mutated: %v", got)
	}
}
