package ai_test

import (
	"github.com/masahiro331/wisteria/internal/ai"
	"github.com/masahiro331/wisteria/internal/ai/ollama"
)

// Compile-time guarantee that ollama.Client satisfies ai.Summarizer.
// If a future provider needs a different signature, this is the line
// that catches the divergence at build time.
var _ ai.Summarizer = (*ollama.Client)(nil)
