package ollama

import (
	"errors"
	"fmt"
)

// AdvisoryAISummary is the structured output produced by the LLM for one
// UnifiedAdvisory. Pointer / slice fields follow design §5: unknown string
// fields are null, unknown array fields are []. Confidence is 0.0–1.0.
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

// Validate enforces design §5 constraints that the JSON Schema cannot
// fully express on the model side: title must be non-empty (the model
// is instructed to summarize, an empty title is never the correct
// answer), and confidence must be within [0, 1]. Note that confidence
// presence (vs. an explicit zero) is checked one level up in the
// client because that needs the raw JSON map. JSON type mismatches
// fail earlier at json.Unmarshal time. Missing array fields are
// tolerated and normalized to empty slices by Normalize, so they do
// not show up here.
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

// summarySchema is the JSON Schema sent in the Ollama request `format`
// field. Hand-written per design §8 to keep it minimal and free of
// `$defs` / `$schema` / draft-specific features the model might ignore.
func summarySchema() map[string]any {
	stringOrNull := []string{"string", "null"}
	stringArray := map[string]any{
		"type":  "array",
		"items": map[string]any{"type": "string"},
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"title":               map[string]any{"type": "string"},
			"affected_products":   stringArray,
			"vulnerability_type":  map[string]any{"type": stringOrNull},
			"impact":              map[string]any{"type": stringOrNull},
			"affected_versions":   stringArray,
			"fixed_versions":      stringArray,
			"severity":            map[string]any{"type": stringOrNull},
			"exploitation_status": map[string]any{"type": stringOrNull},
			"recommended_action":  map[string]any{"type": stringOrNull},
			"confidence": map[string]any{
				"type":    "number",
				"minimum": 0,
				"maximum": 1,
			},
			"missing_information": stringArray,
		},
		"required": []string{
			"title",
			"affected_products",
			"vulnerability_type",
			"impact",
			"affected_versions",
			"fixed_versions",
			"severity",
			"exploitation_status",
			"recommended_action",
			"confidence",
			"missing_information",
		},
	}
}
