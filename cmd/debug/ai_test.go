package debug_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/cmd"
	"github.com/masahiro331/wisteria/cmd/debug"
	"github.com/masahiro331/wisteria/internal/ai"
	"github.com/masahiro331/wisteria/internal/unified"
)

type fakeSummarizer struct {
	gotAdvisory unified.UnifiedAdvisory
	out         *ai.AdvisoryAISummary
	err         error
	called      int
}

func (f *fakeSummarizer) Summarize(_ context.Context, advisory unified.UnifiedAdvisory) (*ai.AdvisoryAISummary, error) {
	f.called++
	f.gotAdvisory = advisory
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

func sampleSummary() *ai.AdvisoryAISummary {
	return &ai.AdvisoryAISummary{
		Title:              "Heap overflow in libfoo",
		AffectedProducts:   []string{"libfoo"},
		AffectedVersions:   []string{"<1.2.3"},
		FixedVersions:      []string{"1.2.3"},
		MissingInformation: []string{},
		Confidence:         0.8,
	}
}

func runDebugAI(t *testing.T, fake *fakeSummarizer, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	// Build a root command with our debug subtree, but swap the AI
	// summarize subcommand for one whose factory returns the fake.
	root := cmd.NewRootCmd()
	// Replace the existing `debug` subcommand with our own that uses
	// the test factory. Cobra has no remove-by-name helper, so do it
	// the manual way.
	for _, sub := range root.Commands() {
		if sub.Name() == "debug" {
			root.RemoveCommand(sub)
			break
		}
	}
	dbg := debug.NewCmdWithFactory(func(_ debug.AISummarizeOptions) (ai.Summarizer, error) {
		return fake, nil
	})
	root.AddCommand(dbg)

	full := append([]string{"debug", "ai", "summarize"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func writeUnifiedAdvisory(t *testing.T, cacheDir, primaryID string) {
	t.Helper()
	rec := unified.UnifiedAdvisory{PrimaryID: primaryID}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// Mirror writer's CVE bucket layout: unified/cve/<year>/<id>.json
	// Year is the 4-digit slice after "CVE-".
	year := primaryID[4:8]
	dir := filepath.Join(cacheDir, "unified", "cve", year)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, primaryID+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDebugAI_Stdin_PrintsSummary(t *testing.T) {
	fake := &fakeSummarizer{out: sampleSummary()}
	advisory := unified.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}
	body, err := json.Marshal(advisory)
	if err != nil {
		t.Fatal(err)
	}

	// Cobra reads stdin from os.Stdin; redirect via a pipe.
	withStdin(t, body, func() {
		stdout, _, err := runDebugAI(t, fake, "--from-stdin")
		if err != nil {
			t.Fatalf("debug ai summarize: %v", err)
		}
		if fake.called != 1 {
			t.Errorf("Summarize called %d times, want 1", fake.called)
		}
		if fake.gotAdvisory.PrimaryID != "CVE-2024-0001" {
			t.Errorf("got advisory PrimaryID = %q, want CVE-2024-0001", fake.gotAdvisory.PrimaryID)
		}
		var got ai.AdvisoryAISummary
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("decode stdout JSON: %v\n%s", err, stdout)
		}
		if got.Title != "Heap overflow in libfoo" {
			t.Errorf("Title = %q", got.Title)
		}
	})
}

func TestDebugAI_ID_ReadsFromCacheDir(t *testing.T) {
	cacheDir := t.TempDir()
	writeUnifiedAdvisory(t, cacheDir, "CVE-2024-0001")

	fake := &fakeSummarizer{out: sampleSummary()}
	stdout, _, err := runDebugAI(t, fake, "--id", "CVE-2024-0001", "--cache-dir", cacheDir)
	if err != nil {
		t.Fatalf("debug ai summarize: %v", err)
	}
	if fake.called != 1 {
		t.Errorf("Summarize called %d times, want 1", fake.called)
	}
	if fake.gotAdvisory.PrimaryID != "CVE-2024-0001" {
		t.Errorf("got advisory PrimaryID = %q, want CVE-2024-0001", fake.gotAdvisory.PrimaryID)
	}
	if !strings.Contains(stdout, "Heap overflow") {
		t.Errorf("stdout missing summary title: %s", stdout)
	}
}

func TestDebugAI_ID_NotFound(t *testing.T) {
	cacheDir := t.TempDir()
	fake := &fakeSummarizer{out: sampleSummary()}
	_, _, err := runDebugAI(t, fake, "--id", "CVE-2099-9999", "--cache-dir", cacheDir)
	if err == nil {
		t.Fatal("debug ai summarize returned nil error, want not-found")
	}
	if fake.called != 0 {
		t.Errorf("Summarize called %d times, want 0 (advisory not found)", fake.called)
	}
}

func TestDebugAI_RequiresExactlyOneInputMode(t *testing.T) {
	t.Parallel()
	t.Run("neither", func(t *testing.T) {
		fake := &fakeSummarizer{out: sampleSummary()}
		_, _, err := runDebugAI(t, fake)
		if err == nil {
			t.Fatal("expected error when neither --from-stdin nor --id is given")
		}
	})
	t.Run("both", func(t *testing.T) {
		fake := &fakeSummarizer{out: sampleSummary()}
		_, _, err := runDebugAI(t, fake, "--from-stdin", "--id", "CVE-2024-0001")
		if err == nil {
			t.Fatal("expected error when both --from-stdin and --id are given")
		}
	})
}

func TestDebugAI_PropagatesSummarizerError(t *testing.T) {
	fake := &fakeSummarizer{err: errors.New("boom")}
	advisory := unified.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}
	body, _ := json.Marshal(advisory)

	withStdin(t, body, func() {
		_, _, err := runDebugAI(t, fake, "--from-stdin")
		if err == nil {
			t.Fatal("expected error when summarizer fails")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("error does not include underlying message: %v", err)
		}
	})
}

func TestDebugAI_RejectsInvalidStdinJSON(t *testing.T) {
	fake := &fakeSummarizer{out: sampleSummary()}
	withStdin(t, []byte("not json {{{"), func() {
		_, _, err := runDebugAI(t, fake, "--from-stdin")
		if err == nil {
			t.Fatal("expected error on invalid stdin JSON")
		}
		if fake.called != 0 {
			t.Errorf("Summarize should not be called when stdin is malformed")
		}
	})
}

// runDebugAIWithFactory is runDebugAI with caller-supplied factory.
// Use it when the test cares about what flags reach AISummarizeOptions
// (e.g. --think wiring) or when the test wants the production
// defaultAIFactory exercised (factory == nil).
func runDebugAIWithFactory(t *testing.T, factory debug.AIFactory, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := cmd.NewRootCmd()
	for _, sub := range root.Commands() {
		if sub.Name() == "debug" {
			root.RemoveCommand(sub)
			break
		}
	}
	root.AddCommand(debug.NewCmdWithFactory(factory))

	full := append([]string{"debug", "ai", "summarize"}, args...)
	root.SetArgs(full)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	err = root.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestDebugAI_UnknownProviderRejected(t *testing.T) {
	advisory := unified.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}
	body, _ := json.Marshal(advisory)

	withStdin(t, body, func() {
		// nil factory → defaultAIFactory, which is the code path that
		// rejects unknown providers.
		_, _, err := runDebugAIWithFactory(t, nil, "--from-stdin", "--provider", "bogus")
		if err == nil {
			t.Fatal("expected error for unknown --provider")
		}
		if !strings.Contains(err.Error(), "unknown --provider") {
			t.Errorf("error does not mention 'unknown --provider': %v", err)
		}
	})
}

func TestDebugAI_ThinkFlagReachesOptions(t *testing.T) {
	advisory := unified.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}
	body, _ := json.Marshal(advisory)

	var captured debug.AISummarizeOptions
	fake := &fakeSummarizer{out: sampleSummary()}
	factory := func(opts debug.AISummarizeOptions) (ai.Summarizer, error) {
		captured = opts
		return fake, nil
	}

	withStdin(t, body, func() {
		if _, _, err := runDebugAIWithFactory(t, factory, "--from-stdin", "--think"); err != nil {
			t.Fatalf("debug ai summarize: %v", err)
		}
	})

	if !captured.Think {
		t.Errorf("AISummarizeOptions.Think = false, want true (--think flag should propagate)")
	}
}

type erroringWriter struct{}

func (erroringWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write boom")
}

func TestDebugAI_StdoutEncodeErrorSurfaces(t *testing.T) {
	advisory := unified.UnifiedAdvisory{PrimaryID: "CVE-2024-0001"}
	body, _ := json.Marshal(advisory)

	fake := &fakeSummarizer{out: sampleSummary()}
	root := cmd.NewRootCmd()
	for _, sub := range root.Commands() {
		if sub.Name() == "debug" {
			root.RemoveCommand(sub)
			break
		}
	}
	root.AddCommand(debug.NewCmdWithFactory(func(_ debug.AISummarizeOptions) (ai.Summarizer, error) {
		return fake, nil
	}))
	root.SetArgs([]string{"debug", "ai", "summarize", "--from-stdin"})
	root.SetOut(erroringWriter{})
	root.SetErr(&bytes.Buffer{})

	withStdin(t, body, func() {
		err := root.ExecuteContext(context.Background())
		if err == nil {
			t.Fatal("expected error when stdout encoder fails")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Errorf("error does not include underlying writer message: %v", err)
		}
	})
}

// withStdin replaces os.Stdin for the duration of fn with a pipe whose
// read end yields body. Restores os.Stdin on exit.
func withStdin(t *testing.T, body []byte, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
	go func() {
		_, _ = w.Write(body)
		_ = w.Close()
	}()
	fn()
}

// Compile-time guarantee: NewCmdWithFactory still hands us back a
// *cobra.Command — if the signature drifts the test file fails to
// build. Anchor exists to catch accidental API breakage.
var _ *cobra.Command = debug.NewCmdWithFactory(nil)
