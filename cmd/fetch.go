package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/cve"
	"github.com/masahiro331/wisteria/internal/fetcher/epss"
	"github.com/masahiro331/wisteria/internal/fetcher/exploitdb"
	"github.com/masahiro331/wisteria/internal/fetcher/kev"
	"github.com/masahiro331/wisteria/internal/fetcher/osv"
	"github.com/masahiro331/wisteria/internal/fetcher/progress"
)

// fetchOptions bundles common per-invocation knobs read from CLI flags.
type fetchOptions struct {
	cacheDir    string
	concurrency int
	retries     int
	tracker     *progress.Tracker
	// osvExclude overrides the OSV fetcher's default ecosystem
	// exclusion list; nil means "flag not set, keep the default".
	osvExclude []string
}

// fetcherFactory builds a Fetcher with the resolved options applied.
type fetcherFactory func(opts fetchOptions) fetcher.Fetcher

func osvFactory(opts fetchOptions) fetcher.Fetcher {
	osvOpts := []osv.Option{
		osv.WithCacheDir(opts.cacheDir),
		osv.WithProgress(opts.tracker),
		osv.WithConcurrency(opts.concurrency),
		osv.WithRetries(opts.retries),
	}
	if opts.osvExclude != nil {
		osvOpts = append(osvOpts, osv.WithExcludedEcosystems(opts.osvExclude))
	}
	return osv.New(osvOpts...)
}

func cveFactory(opts fetchOptions) fetcher.Fetcher {
	return cve.New(
		cve.WithCacheDir(opts.cacheDir),
		cve.WithProgress(opts.tracker),
		cve.WithRetries(opts.retries),
	)
}

func kevFactory(opts fetchOptions) fetcher.Fetcher {
	return kev.New(
		kev.WithCacheDir(opts.cacheDir),
		kev.WithProgress(opts.tracker),
		kev.WithRetries(opts.retries),
	)
}

func epssFactory(opts fetchOptions) fetcher.Fetcher {
	return epss.New(
		epss.WithCacheDir(opts.cacheDir),
		epss.WithProgress(opts.tracker),
		epss.WithRetries(opts.retries),
	)
}

func exploitDBFactory(opts fetchOptions) fetcher.Fetcher {
	return exploitdb.New(
		exploitdb.WithCacheDir(opts.cacheDir),
		exploitdb.WithProgress(opts.tracker),
		exploitdb.WithRetries(opts.retries),
	)
}

func optionsFromCmd(cmd *cobra.Command) fetchOptions {
	cacheDir, _ := cmd.Flags().GetString(cacheDirFlag)
	concurrency, _ := cmd.Flags().GetInt(concurrencyFlag)
	retries, _ := cmd.Flags().GetInt(retriesFlag)
	opts := fetchOptions{
		cacheDir:    cacheDir,
		concurrency: concurrency,
		retries:     retries,
		tracker:     newTracker(cmd.ErrOrStderr()),
	}
	if cmd.Flags().Changed(osvExcludeFlag) {
		vals, _ := cmd.Flags().GetStringSlice(osvExcludeFlag)
		opts.osvExclude = normalizeExcludes(vals)
	}
	return opts
}

// normalizeExcludes drops empty entries so `--osv-exclude=""` cleanly
// means "exclude nothing" (pflag parses the empty value as [""]).
// A non-nil (possibly empty) slice signals "flag was set".
func normalizeExcludes(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func newFetchCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Download vulnerability data from upstream sources",
	}
	// HTTP-specific persistent flags live here, not on root, so they
	// don't appear on non-fetch subcommands (e.g. `wisteria debug index`)
	// where they'd be no-ops.
	c.PersistentFlags().Int(
		concurrencyFlag, 4,
		"max parallel downloads (applies where the source has multiple files, e.g. OSV)",
	)
	c.PersistentFlags().Int(
		retriesFlag, 3,
		"max attempts per HTTP request before giving up (retries on 5xx and transport errors)",
	)
	c.PersistentFlags().StringSlice(
		osvExcludeFlag, nil,
		"override the default OSV ecosystem exclusion list (comma-separated upstream names; pass \"\" to fetch everything)",
	)
	c.AddCommand(
		newFetchSourceCmd("osv", "Fetch OSV vulnerability data", osvFactory),
		newFetchSourceCmd("cve", "Fetch MITRE CVEListV5 data", cveFactory),
		newFetchSourceCmd("kev", "Fetch CISA Known Exploited Vulnerabilities catalog", kevFactory),
		newFetchSourceCmd("epss", "Fetch FIRST EPSS daily score catalog", epssFactory),
		newFetchSourceCmd("exploitdb", "Fetch Exploit-DB files_exploits.csv catalog", exploitDBFactory),
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
			factories := []fetcherFactory{osvFactory, cveFactory, kevFactory, epssFactory, exploitDBFactory}
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
