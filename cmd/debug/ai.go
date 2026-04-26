package debug

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/ai"
	"github.com/masahiro331/wisteria/internal/ai/ollama"
	"github.com/masahiro331/wisteria/internal/unified"
	"github.com/masahiro331/wisteria/internal/unified/writer"
	"github.com/masahiro331/wisteria/internal/x/cachedir"
)

// AISummarizeOptions captures the per-invocation knobs the user passes
// on the command line. The factory function in NewCmdWithFactory
// receives this so it can build any provider it likes; the production
// factory (defaultAIFactory) only knows how to build *ollama.Client
// for now.
type AISummarizeOptions struct {
	Provider string // e.g. "ollama"; today only ollama is wired
	Model    string // pass-through to the provider
	Endpoint string // pass-through to the provider
	Think    bool   // opt-in to provider-side chain-of-thought
}

// AIFactory builds a provider-specific Summarizer from the user's
// flags. Tests pass a factory that returns a fake; production passes
// defaultAIFactory.
type AIFactory func(AISummarizeOptions) (ai.Summarizer, error)

// newAICmd builds `wisteria debug ai` and its `summarize` subcommand.
// The factory is injected so tests can swap in a fake summarizer
// without spinning up an Ollama process.
func newAICmd(factory AIFactory) *cobra.Command {
	c := &cobra.Command{
		Use:   "ai",
		Short: "AI helpers (developer tool)",
	}
	c.AddCommand(newAISummarizeCmd(factory))
	return c
}

func newAISummarizeCmd(factory AIFactory) *cobra.Command {
	var (
		fromStdin bool
		id        string
		opts      AISummarizeOptions
	)
	c := &cobra.Command{
		Use:   "summarize",
		Short: "Summarize one UnifiedAdvisory using a Summarizer provider (debug-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if fromStdin == (id != "") {
				// either both true or both false
				return errors.New("exactly one of --from-stdin or --id is required")
			}

			advisory, err := loadAdvisory(cmd, fromStdin, id)
			if err != nil {
				return err
			}

			summarizer, err := factory(opts)
			if err != nil {
				return fmt.Errorf("build summarizer: %w", err)
			}

			summary, err := summarizer.Summarize(cmd.Context(), advisory)
			if err != nil {
				return fmt.Errorf("summarize: %w", err)
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(summary)
		},
	}
	c.Flags().BoolVar(&fromStdin, "from-stdin", false, "Read a UnifiedAdvisory JSON document from stdin")
	c.Flags().StringVar(&id, "id", "", "Read a UnifiedAdvisory by PrimaryID from <cache-dir>/unified/")
	c.Flags().StringVar(&opts.Provider, "provider", "ollama", "AI provider (today only \"ollama\" is implemented)")
	c.Flags().StringVar(&opts.Model, "model", "", "Provider-specific model name (e.g. qwen3:8b)")
	c.Flags().StringVar(&opts.Endpoint, "endpoint", "", "Provider HTTP endpoint (e.g. http://localhost:11434)")
	c.Flags().BoolVar(&opts.Think, "think", false, "Enable chain-of-thought on the provider (default off — qwen3 burns num_predict on it)")
	return c
}

func loadAdvisory(cmd *cobra.Command, fromStdin bool, id string) (unified.UnifiedAdvisory, error) {
	if fromStdin {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return unified.UnifiedAdvisory{}, fmt.Errorf("read stdin: %w", err)
		}
		var advisory unified.UnifiedAdvisory
		if err := json.Unmarshal(body, &advisory); err != nil {
			return unified.UnifiedAdvisory{}, fmt.Errorf("decode UnifiedAdvisory from stdin: %w", err)
		}
		return advisory, nil
	}

	cacheDirOverride, _ := cmd.Flags().GetString("cache-dir")
	root, err := cachedir.Root(cacheDirOverride)
	if err != nil {
		return unified.UnifiedAdvisory{}, err
	}
	outDir, err := writer.OutDir(root)
	if err != nil {
		return unified.UnifiedAdvisory{}, fmt.Errorf("resolve unified dir: %w", err)
	}

	path, ok := writer.CVEPath(outDir, id)
	if !ok {
		return unified.UnifiedAdvisory{}, fmt.Errorf("--id %q is not yet supported (only CVE-YYYY-NNNN ids are routed; standalone lookup is a follow-up)", id)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return unified.UnifiedAdvisory{}, fmt.Errorf("read %s: %w", path, err)
	}
	var advisory unified.UnifiedAdvisory
	if err := json.Unmarshal(body, &advisory); err != nil {
		return unified.UnifiedAdvisory{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return advisory, nil
}

// defaultAIFactory builds production-flavored summarizers from the
// CLI options. Today the only supported provider is "ollama" — adding
// "anthropic" or "bedrock" later is a one-case extension here.
func defaultAIFactory(opts AISummarizeOptions) (ai.Summarizer, error) {
	switch opts.Provider {
	case "", "ollama":
		c := &ollama.Client{Endpoint: opts.Endpoint, Model: opts.Model}
		if opts.Think {
			t := true
			c.Think = &t
		}
		return c, nil
	default:
		return nil, fmt.Errorf("unknown --provider %q (supported: ollama)", opts.Provider)
	}
}
