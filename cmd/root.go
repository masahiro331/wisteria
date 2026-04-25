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
	root.PersistentFlags().String(
		cacheDirFlag, "",
		"directory for downloaded data (overrides $WISTERIA_CACHE_DIR; defaults to user cache dir)",
	)
	root.PersistentFlags().Int(
		concurrencyFlag, 4,
		"max parallel downloads (applies where the source has multiple files, e.g. OSV)",
	)
	root.PersistentFlags().Int(
		retriesFlag, 3,
		"max attempts per HTTP request before giving up (retries on 5xx and transport errors)",
	)
	root.AddCommand(newFetchCmd())
	root.AddCommand(debug.NewCmd())
	return root
}
