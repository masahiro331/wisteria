package ollama_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/masahiro331/wisteria/internal/ai/ollama"
	"github.com/masahiro331/wisteria/internal/unified"
)

func sampleAdvisory() unified.UnifiedAdvisory {
	return unified.UnifiedAdvisory{
		PrimaryID: "CVE-2024-0001",
	}
}

type capturedRequest struct {
	method      string
	path        string
	contentType string
	body        map[string]any
}

// recordingServer replies with a valid (but minimal) chat response and
// captures the incoming request so tests can assert on it.
func recordingServer(t *testing.T) (*httptest.Server, *capturedRequest) {
	t.Helper()
	got := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.contentType = r.Header.Get("Content-Type")
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(raw, &got.body); err != nil {
			t.Fatalf("decode body: %v\n%s", err, raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": `{"title":"Example","affected_products":[],"affected_versions":[],"fixed_versions":[],"confidence":0,"missing_information":[]}`,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestClient_Summarize_HTTPMetadata(t *testing.T) {
	t.Parallel()
	srv, got := recordingServer(t)

	c := &ollama.Client{Endpoint: srv.URL}
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.path != "/api/chat" {
		t.Errorf("path = %q, want /api/chat", got.path)
	}
	if got.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got.contentType)
	}
}

func TestClient_Summarize_RequestModelAndStream(t *testing.T) {
	t.Parallel()
	srv, got := recordingServer(t)

	c := &ollama.Client{Endpoint: srv.URL}
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	if v := got.body["model"]; v != "qwen3:8b" {
		t.Errorf("model = %v, want qwen3:8b", v)
	}
	if v, ok := got.body["stream"].(bool); !ok || v {
		t.Errorf("stream = %v (ok=%v), want false", v, ok)
	}
}

func TestClient_Summarize_RequestFormatSchema(t *testing.T) {
	t.Parallel()
	srv, got := recordingServer(t)

	c := &ollama.Client{Endpoint: srv.URL}
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	format, ok := got.body["format"].(map[string]any)
	if !ok {
		t.Fatalf("format is not an object: %T (%v)", got.body["format"], got.body["format"])
	}
	if format["type"] != "object" {
		t.Errorf("format.type = %v, want object", format["type"])
	}
	props, ok := format["properties"].(map[string]any)
	if !ok {
		t.Fatalf("format.properties is not an object: %T", format["properties"])
	}
	for _, key := range []string{
		"title", "affected_products", "vulnerability_type", "impact",
		"affected_versions", "fixed_versions", "severity",
		"exploitation_status", "recommended_action", "confidence",
		"missing_information",
	} {
		if _, ok := props[key]; !ok {
			t.Errorf("format.properties is missing %q", key)
		}
	}
}

func TestClient_Summarize_RequestOptions(t *testing.T) {
	t.Parallel()
	srv, got := recordingServer(t)

	c := &ollama.Client{Endpoint: srv.URL}
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	options, ok := got.body["options"].(map[string]any)
	if !ok {
		t.Fatalf("options is not an object: %T", got.body["options"])
	}
	for _, tc := range []struct {
		key  string
		want float64
	}{
		{"temperature", 0},
		{"num_ctx", 8192},
		{"num_predict", 1200},
	} {
		if v := options[tc.key]; v != tc.want {
			t.Errorf("options.%s = %v, want %v", tc.key, v, tc.want)
		}
	}
}

func TestClient_Summarize_RequestMessages(t *testing.T) {
	t.Parallel()
	srv, got := recordingServer(t)

	c := &ollama.Client{Endpoint: srv.URL}
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	messages, ok := got.body["messages"].([]any)
	if !ok {
		t.Fatalf("messages is not an array: %T", got.body["messages"])
	}
	if len(messages) < 2 {
		t.Fatalf("messages = %d entries, want at least 2 (system + user)", len(messages))
	}
	first, _ := messages[0].(map[string]any)
	if first["role"] != "system" {
		t.Errorf("messages[0].role = %v, want system", first["role"])
	}
	if s, _ := first["content"].(string); s == "" {
		t.Error("messages[0].content is empty")
	}
	last, _ := messages[len(messages)-1].(map[string]any)
	if last["role"] != "user" {
		t.Errorf("messages[last].role = %v, want user", last["role"])
	}
	userContent, _ := last["content"].(string)
	if !strings.Contains(userContent, "CVE-2024-0001") {
		t.Errorf("messages[last].content does not mention PrimaryID; got: %q", userContent)
	}
}

func TestClient_Summarize_DecodesContent(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"message": map[string]any{
				"role": "assistant",
				"content": `{
					"title": "Heap overflow in libfoo",
					"affected_products": ["libfoo"],
					"vulnerability_type": "heap-overflow",
					"impact": "RCE",
					"affected_versions": ["<1.2.3"],
					"fixed_versions": ["1.2.3"],
					"severity": "high",
					"exploitation_status": "kev",
					"recommended_action": "Upgrade to 1.2.3",
					"confidence": 0.8,
					"missing_information": []
				}`,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	c := &ollama.Client{Endpoint: srv.URL}
	out, err := c.Summarize(context.Background(), sampleAdvisory())
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	if out.Title != "Heap overflow in libfoo" {
		t.Errorf("Title = %q", out.Title)
	}
	if len(out.AffectedProducts) != 1 || out.AffectedProducts[0] != "libfoo" {
		t.Errorf("AffectedProducts = %v", out.AffectedProducts)
	}
	if out.VulnerabilityType == nil || *out.VulnerabilityType != "heap-overflow" {
		t.Errorf("VulnerabilityType = %v", out.VulnerabilityType)
	}
	if out.Confidence != 0.8 {
		t.Errorf("Confidence = %v", out.Confidence)
	}
}

func TestClient_Summarize_DecodeErrorIncludesRawContent(t *testing.T) {
	t.Parallel()

	const raw = "this is definitely not JSON {{{"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": raw,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	c := &ollama.Client{Endpoint: srv.URL}
	_, err := c.Summarize(context.Background(), sampleAdvisory())
	if err == nil {
		t.Fatal("Summarize returned nil error, want decode error")
	}
	if !strings.Contains(err.Error(), raw) {
		t.Errorf("error does not include raw content: %v", err)
	}
}

func TestClient_Summarize_DefaultsModelAndEndpoint(t *testing.T) {
	t.Parallel()

	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel, _ = body["model"].(string)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]any{
				"content": `{"title":"x","affected_products":[],"affected_versions":[],"fixed_versions":[],"confidence":0,"missing_information":[]}`,
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := &ollama.Client{Endpoint: srv.URL} // Model intentionally empty
	if _, err := c.Summarize(context.Background(), sampleAdvisory()); err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if gotModel != "qwen3:8b" {
		t.Errorf("default model = %q, want qwen3:8b", gotModel)
	}
}

func TestClient_Summarize_HTTPErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := &ollama.Client{Endpoint: srv.URL}
	_, err := c.Summarize(context.Background(), sampleAdvisory())
	if err == nil {
		t.Fatal("Summarize returned nil error, want HTTP 500 error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error does not mention status: %v", err)
	}
}

func TestClient_Summarize_ContextCancellation(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(block)
		srv.Close()
	})

	c := &ollama.Client{Endpoint: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Summarize(ctx, sampleAdvisory())
	if err == nil {
		t.Fatal("Summarize returned nil error, want context error")
	}
	if ctx.Err() == nil {
		t.Errorf("context not cancelled: %v", ctx.Err())
	}
}
