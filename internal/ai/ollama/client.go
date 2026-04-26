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

	"github.com/masahiro331/wisteria/internal/unified"
)

const (
	defaultEndpoint = "http://localhost:11434"
	defaultModel    = "qwen3:8b"

	chatPath = "/api/chat"

	// Runtime parameters per design §12 (M1 16GB initial values).
	defaultTemperature = 0
	defaultNumCtx      = 8192
	defaultNumPredict  = 1200

	systemPrompt = "You summarize vulnerability advisories for security engineers.\n" +
		"Return only JSON that matches the provided schema.\n" +
		"Do not invent facts.\n" +
		"Use null or [] when the input does not contain enough information.\n" +
		"Prefer concrete affected products, versions, fixed versions, impact, and recommended action."
)

// Client calls a local Ollama HTTP endpoint. Zero value is not usable;
// callers should set Endpoint (or rely on the default localhost) and
// optionally override Model and HTTP. Safe for concurrent use as long
// as the underlying http.Client is.
type Client struct {
	Endpoint string       // default: http://localhost:11434
	Model    string       // default: qwen3:8b
	HTTP     *http.Client // default: http.DefaultClient
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatOptions struct {
	Temperature int `json:"temperature"`
	NumCtx      int `json:"num_ctx"`
	NumPredict  int `json:"num_predict"`
}

type chatRequest struct {
	Model    string         `json:"model"`
	Stream   bool           `json:"stream"`
	Format   map[string]any `json:"format"`
	Options  chatOptions    `json:"options"`
	Messages []chatMessage  `json:"messages"`
}

type chatResponse struct {
	Message chatMessage `json:"message"`
}

// Summarize sends one UnifiedAdvisory to Ollama and decodes the response
// content into AdvisoryAISummary. Decode failures wrap the raw model
// content so callers can inspect what the model returned.
func (c *Client) Summarize(ctx context.Context, advisory unified.UnifiedAdvisory) (*AdvisoryAISummary, error) {
	advisoryJSON, err := json.Marshal(advisory)
	if err != nil {
		return nil, fmt.Errorf("marshal advisory: %w", err)
	}

	body := chatRequest{
		Model:  c.model(),
		Stream: false,
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

	var summary AdvisoryAISummary
	if err := json.Unmarshal([]byte(decoded.Message.Content), &summary); err != nil {
		return nil, fmt.Errorf("decode model content: %w (raw: %s)", err, decoded.Message.Content)
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

func buildUserPrompt(primaryID string, advisoryJSON []byte) string {
	var b bytes.Buffer
	b.WriteString("Summarize this vulnerability advisory in English.\n\n")
	b.WriteString("PrimaryID: ")
	b.WriteString(primaryID)
	b.WriteString("\n\nInput UnifiedAdvisory JSON:\n")
	b.Write(advisoryJSON)
	return b.String()
}
