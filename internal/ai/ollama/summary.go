package ollama

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
		"type": "object",
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
