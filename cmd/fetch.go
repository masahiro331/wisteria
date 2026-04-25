package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/cve"
	"github.com/masahiro331/wisteria/internal/fetcher/osv"
	"github.com/masahiro331/wisteria/internal/progress"
)

// fetchOptions bundles common per-invocation knobs read from CLI flags.
type fetchOptions struct {
	cacheDir    string
	concurrency int
	tracker     *progress.Tracker
}

// fetcherFactory builds a Fetcher with the resolved options applied.
type fetcherFactory func(opts fetchOptions) fetcher.Fetcher

func osvFactory(opts fetchOptions) fetcher.Fetcher {
	return osv.New(
		osv.WithCacheDir(opts.cacheDir),
		osv.WithProgress(opts.tracker),
		osv.WithConcurrency(opts.concurrency),
	)
}

func cveFactory(opts fetchOptions) fetcher.Fetcher {
	return cve.New(cve.WithCacheDir(opts.cacheDir), cve.WithProgress(opts.tracker))
}

func optionsFromCmd(cmd *cobra.Command) fetchOptions {
	cacheDir, _ := cmd.Flags().GetString(cacheDirFlag)
	concurrency, _ := cmd.Flags().GetInt(concurrencyFlag)
	return fetchOptions{
		cacheDir:    cacheDir,
		concurrency: concurrency,
		tracker:     newTracker(cmd.ErrOrStderr()),
	}
}

func newFetchCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Download vulnerability data from upstream sources",
	}
	c.AddCommand(
		newFetchSourceCmd("osv", "Fetch OSV vulnerability data", osvFactory),
		newFetchSourceCmd("cve", "Fetch MITRE CVEListV5 data", cveFactory),
		newFetchAllCmd(),
	)
	return c
}

// newTracker builds a progress tracker writing to stderr, or returns nil
// when stderr isn't usable (e.g. piped to a non-writer).
func newTracker(out io.Writer) *progress.Tracker {
	if out == nil {
		return nil
	}
	return progress.New(out)
}

func newFetchSourceCmd(use, short string, factory fetcherFactory) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := factory(optionsFromCmd(cmd))
			dir, err := f.Fetch(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "saved %s data to %s\n", f.Name(), dir)
			return nil
		},
	}
}

func newFetchAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all",
		Short: "Fetch every supported source",
		RunE: func(cmd *cobra.Command, _ []string) error {
			factories := []fetcherFactory{osvFactory, cveFactory}
			for _, factory := range factories {
				f := factory(optionsFromCmd(cmd))
				dir, err := f.Fetch(cmd.Context())
				if err != nil {
					return fmt.Errorf("%s: %w", f.Name(), err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "saved %s data to %s\n", f.Name(), dir)
			}
			return nil
		},
	}
}
