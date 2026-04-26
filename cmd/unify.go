package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/unified/pipeline"
)

// newUnifyCmd builds `wisteria unify --cache-dir <path>`. The actual
// Stage 1-4 orchestration lives in internal/unified/pipeline; this
// file owns only flag parsing and pprof.
func newUnifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "unify",
		Short: "Build the unified advisory tree from downloaded sources",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheOverride, _ := cmd.Flags().GetString(cacheDirFlag)
			conc, _ := cmd.Flags().GetInt(concurrencyFlag)
			cpuProfile, _ := cmd.Flags().GetString("cpuprofile")
			if cpuProfile != "" {
				f, err := os.Create(cpuProfile)
				if err != nil {
					return fmt.Errorf("create cpuprofile: %w", err)
				}
				defer f.Close()
				if err := pprof.StartCPUProfile(f); err != nil {
					return fmt.Errorf("start cpuprofile: %w", err)
				}
				defer pprof.StopCPUProfile()
			}
			return pipeline.Run(cmd.Context(), cacheOverride, pipeline.Options{
				Concurrency: conc,
			}, cmd.OutOrStdout())
		},
	}
	c.Flags().Int(
		concurrencyFlag, 0,
		"per-stage worker pool size (default 4× NumCPU)",
	)
	c.Flags().String(
		"cpuprofile", "",
		"write CPU profile to this file (use with `go tool pprof <file>`)",
	)
	return c
}
