package cmd

import "github.com/spf13/cobra"

const cacheDirFlag = "cache-dir"

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
	root.AddCommand(newFetchCmd())
	return root
}
