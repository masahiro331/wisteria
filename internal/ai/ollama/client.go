// Package ollama is a thin REST client for the local Ollama server. It
// exposes Summarize, which sends one UnifiedAdvisory to the configured
// chat model with a JSON-Schema constrained `format` field and decodes
// the structured response into AdvisoryAISummary.
//
// The client is intentionally small: no streaming, no retries, no batch
// orchestration. Higher-level concerns (concurrency control, output
// layout, prompt versioning) live in the caller — see
// docs/design/ai-advisory-summary.md §7 and §9.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/masahiro331/wisteria/internal/ai"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

const (
	defaultEndpoint = "http://localhost:11434"
	defaultModel    = "qwen3:8b"

	chatPath = "/api/chat"

	// Runtime parameters per design §12 (M1 16GB initial values).
	defaultNumCtx     = 8192
	defaultNumPredict = 1200

	systemPrompt = "You summarize vulnerability advisories for security engineers.\n" +
		"Return only JSON that matches the provided schema.\n" +
		"Do not invent facts.\n" +
		"Use null or [] when the input does not contain enough information.\n" +
		"Prefer concrete affected products, versions, fixed versions, impact, and recommended action."
)

// defaultTemperature is split out of the const block above because it
// must be float64 to match chatOptions.Temperature; mixing typed and
// untyped constants in one group trips staticcheck SA9004.
const defaultTemperature float64 = 0

// Client calls a local Ollama HTTP endpoint. The zero value is usable
// and resolves to Endpoint=http://localhost:11434, Model=qwen3:8b,
// HTTP=http.DefaultClient, and think=false; set the fields explicitly
// to override any of them (typically Endpoint in tests, Model when
// falling back to a smaller variant per design §3 fallback, Think to
// re-enable chain-of-thought on a model that benefits from it). Safe
// for concurrent use as long as the underlying http.Client is.
type Client struct {
	Endpoint string       // default: http://localhost:11434
	Model    string       // default: qwen3:8b
	HTTP     *http.Client // default: http.DefaultClient
	// Think controls Ollama's `think` flag. nil means "default to
	// false" — qwen3 is a thinking model, and with think enabled it
	// burns num_predict on a hidden <think> block and returns an
	// empty assistant content. Set to a pointer to true only when
	// running a model that should keep its reasoning step.
	Think *bool
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatOptions struct {
	Temperature float64 `json:"temperature"`
	NumCtx      int     `json:"num_ctx"`
	NumPredict  int     `json:"num_predict"`
}

type chatRequest struct {
	Model    string         `json:"model"`
	Stream   bool           `json:"stream"`
	Think    bool           `json:"think"`
	Format   map[string]any `json:"format"`
	Options  chatOptions    `json:"options"`
	Messages []chatMessage  `json:"messages"`
}

type chatResponse struct {
	Message chatMessage `json:"message"`
}

// Summarize sends one UnifiedAdvisory to Ollama and decodes the response
// content into ai.AdvisoryAISummary. Decode failures wrap the raw
// model content so callers can inspect what the model returned. The
// method makes *Client satisfy ai.Summarizer.
func (c *Client) Summarize(ctx context.Context, advisory advisory.UnifiedAdvisory) (*ai.AdvisoryAISummary, error) {
	advisoryJSON, err := json.Marshal(advisory)
	if err != nil {
		return nil, fmt.Errorf("marshal advisory: %w", err)
	}

	body := chatRequest{
		Model:  c.model(),
		Stream: false,
		Think:  c.think(),
		Format: summarySchema(),
		Options: chatOptions{
			Temperature: defaultTemperature,
			NumCtx:      defaultNumCtx,
			NumPredict:  defaultNumPredict,
		},
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(advisory.PrimaryID, advisoryJSON)},
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint()+chatPath, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(respBody))
	}

	var decoded chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	contentBytes := []byte(decoded.Message.Content)

	// First pass into a generic map so we can detect *missing* required
	// scalars (e.g. confidence) — once decoded into a struct, an absent
	// number key and an explicit zero are indistinguishable.
	var raw map[string]any
	if err := json.Unmarshal(contentBytes, &raw); err != nil {
		return nil, fmt.Errorf("decode model content: %w (raw: %s)", err, decoded.Message.Content)
	}
	if _, ok := raw["confidence"]; !ok {
		return nil, fmt.Errorf("invalid model output: confidence is missing (raw: %s)", decoded.Message.Content)
	}

	var summary ai.AdvisoryAISummary
	if err := json.Unmarshal(contentBytes, &summary); err != nil {
		return nil, fmt.Errorf("decode model content: %w (raw: %s)", err, decoded.Message.Content)
	}
	summary.Normalize()
	if err := summary.Validate(); err != nil {
		return nil, fmt.Errorf("invalid model output: %w (raw: %s)", err, decoded.Message.Content)
	}
	return &summary, nil
}

func (c *Client) endpoint() string {
	if c.Endpoint == "" {
		return defaultEndpoint
	}
	return c.Endpoint
}

func (c *Client) model() string {
	if c.Model == "" {
		return defaultModel
	}
	return c.Model
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP == nil {
		return http.DefaultClient
	}
	return c.HTTP
}

func (c *Client) think() bool {
	if c.Think == nil {
		return false
	}
	return *c.Think
}

func buildUserPrompt(primaryID string, advisoryJSON []byte) string {
	var b bytes.Buffer
	b.WriteString("Summarize this vulnerability advisory in English.\n\n")
	b.WriteString("PrimaryID: ")
	b.WriteString(primaryID)
	b.WriteString("\n\nInput UnifiedAdvisory JSON:\n")
	b.Write(advisoryJSON)
	return b.String()
}
