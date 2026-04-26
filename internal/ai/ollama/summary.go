package ollama

// summarySchema is the JSON Schema sent in the Ollama request `format`
// field. Hand-written per design §8 to keep it minimal and free of
// `$defs` / `$schema` / draft-specific features the model might ignore.
// The shape mirrors ai.AdvisoryAISummary; if you add a field there,
// add it here too (TestClient_Summarize_RequestFormatSchema pins the
// link).
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
