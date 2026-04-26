// Package ai is the provider-neutral surface of the AI layer.
//
// Right now it exposes the Summarizer task interface and the structured
// output type AdvisoryAISummary. Future task interfaces (Labeler,
// ExploitAnalyzer, …) will live alongside Summarizer; provider
// implementations live under internal/ai/<provider>/. The first such
// implementation is internal/ai/ollama; planned future providers
// include the Anthropic API client and AWS Bedrock — neither is built
// yet, the interface is sized so they can be added without touching
// call sites.
package ai

import (
	"context"
	"errors"
	"fmt"

	"github.com/masahiro331/wisteria/internal/unified"
)

// Summarizer turns one UnifiedAdvisory into a structured English
// AdvisoryAISummary. It is the smallest useful task unit; future tasks
// (labeling, exploit analysis) get their own sibling interfaces so a
// provider can implement only the tasks it supports.
type Summarizer interface {
	Summarize(ctx context.Context, advisory unified.UnifiedAdvisory) (*AdvisoryAISummary, error)
}

// AdvisoryAISummary is the structured output produced by the LLM for
// one UnifiedAdvisory. Pointer / slice fields follow design §5: unknown
// string fields are null, unknown array fields are []. Confidence is
// 0.0–1.0.
type AdvisoryAISummary struct {
	Title              string   `json:"title"`
	AffectedProducts   []string `json:"affected_products"`
	VulnerabilityType  *string  `json:"vulnerability_type"`
	Impact             *string  `json:"impact"`
	AffectedVersions   []string `json:"affected_versions"`
	FixedVersions      []string `json:"fixed_versions"`
	Severity           *string  `json:"severity"`
	ExploitationStatus *string  `json:"exploitation_status"`
	RecommendedAction  *string  `json:"recommended_action"`
	Confidence         float64  `json:"confidence"`
	MissingInformation []string `json:"missing_information"`
}

// Validate enforces design §5 constraints that a JSON Schema sent to
// the model cannot fully express on the model side: title must be
// non-empty (the model is instructed to summarize, an empty title is
// never the correct answer), and confidence must be within [0, 1].
// Note that confidence presence (vs. an explicit zero) must be checked
// at decode time by the provider because that needs the raw JSON map.
// JSON type mismatches fail earlier at json.Unmarshal time. Missing
// array fields are tolerated and normalized to empty slices by
// Normalize, so they do not show up here.
func (s *AdvisoryAISummary) Validate() error {
	if s.Title == "" {
		return errors.New("title is empty")
	}
	if s.Confidence < 0 || s.Confidence > 1 {
		return fmt.Errorf("confidence %v out of range [0, 1]", s.Confidence)
	}
	return nil
}

// Normalize replaces nil array fields with empty slices so callers can
// rely on len() == 0 rather than nil-checking each one. Mutates the
// receiver in place. Existing non-nil slices are left untouched.
func (s *AdvisoryAISummary) Normalize() {
	if s.AffectedProducts == nil {
		s.AffectedProducts = []string{}
	}
	if s.AffectedVersions == nil {
		s.AffectedVersions = []string{}
	}
	if s.FixedVersions == nil {
		s.FixedVersions = []string{}
	}
	if s.MissingInformation == nil {
		s.MissingInformation = []string{}
	}
}
