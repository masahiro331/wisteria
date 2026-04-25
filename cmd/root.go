package cmd

import (
	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/cmd/debug"
)

const (
	cacheDirFlag    = "cache-dir"
	concurrencyFlag = "concurrency"
	retriesFlag     = "retries"
)

// NewRootCmd builds the top-level wisteria command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "wisteria",
		Short:         "Free, fast vulnerability database builder",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// --cache-dir is the only truly cross-cutting flag: both `fetch`
	// (write target) and `debug` (read target) need it. HTTP-specific
	// knobs like --retries / --concurrency live on `fetch` itself so
	// they don't appear as no-op flags on `debug` subcommands.
	root.PersistentFlags().String(
		cacheDirFlag, "",
		"directory for downloaded data (overrides $WISTERIA_CACHE_DIR; defaults to user cache dir)",
	)
	root.AddCommand(newFetchCmd())
	root.AddCommand(debug.NewCmd())
	return root
}
