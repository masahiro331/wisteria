package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/fetcher"
	"github.com/masahiro331/wisteria/internal/fetcher/cve"
	"github.com/masahiro331/wisteria/internal/fetcher/osv"
)

// fetcherFactory builds a Fetcher with the resolved cache directory applied.
type fetcherFactory func(cacheDir string) fetcher.Fetcher

func osvFactory(cacheDir string) fetcher.Fetcher { return osv.New(osv.WithCacheDir(cacheDir)) }
func cveFactory(cacheDir string) fetcher.Fetcher { return cve.New(cve.WithCacheDir(cacheDir)) }

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

func newFetchSourceCmd(use, short string, factory fetcherFactory) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cacheDir, _ := cmd.Flags().GetString(cacheDirFlag)
			f := factory(cacheDir)
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
			cacheDir, _ := cmd.Flags().GetString(cacheDirFlag)
			factories := []fetcherFactory{osvFactory, cveFactory}
			for _, factory := range factories {
				f := factory(cacheDir)
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
