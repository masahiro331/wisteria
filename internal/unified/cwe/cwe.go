// Package cwe maps CWE identifiers to their official MITRE names. The
// table lives in catalog_gen.go, regenerated from the MITRE catalog by
// tools/cwe-catalog. Stage 2 (unifier) uses it to give every merged
// Weakness the same canonical name regardless of which source asserted
// the CWE — per-source free text would leak source differences into
// the unified shape.
package cwe

// Name returns the official MITRE name for a CWE identifier of the
// form "CWE-79". Unknown or malformed identifiers (some CNAs emit
// placeholders like "n/a") return "".
func Name(id string) string {
	return names[id]
}
