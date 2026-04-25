// Package debug holds the `wisteria debug` command tree. Each subcommand
// is a thin wrapper that exposes one stage of the unified-advisory
// pipeline (walker, unifier, ...) for running ad-hoc against real data —
// useful for validating merge rules and field coverage before the
// production `wisteria unify` is wired up.
//
// Layout follows design §10: one file per subcommand under cmd/debug/.
package debug

import "github.com/spf13/cobra"

// NewCmd builds the `debug` parent command with all subcommands attached.
// It is exported so cmd.NewRootCmd can register it.
func NewCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "debug",
		Short: "Inspection helpers for the unified-advisory pipeline (developer tool)",
	}
	c.AddCommand(newIndexCmd())
	c.AddCommand(newUnifyCmd())
	return c
}
