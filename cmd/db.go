package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/masahiro331/wisteria/internal/x/cachedir"
	"github.com/masahiro331/wisteria/pkg/advisory"
	"github.com/masahiro331/wisteria/pkg/db"
	_ "github.com/masahiro331/wisteria/pkg/db/fsdb" // register the "fs" DSN scheme
)

const dsnFlag = "dsn"

// newDBCmd builds the `wisteria db` command group: CLI access to the
// built unified DB through the pkg/db driver registry. Subcommands
// mirror the db.Driver API (find / package) plus a single-record `get`
// convenience. The backend is chosen by --dsn, so future drivers
// (s3://, postgres://) work through the same commands.
func newDBCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "db",
		Short: "Query the built unified vulnerability DB",
	}
	c.PersistentFlags().String(
		dsnFlag, "",
		"driver DSN (defaults to fs://<cache-dir>/unified)",
	)
	c.AddCommand(newDBFindCmd(), newDBGetCmd(), newDBPackageCmd())
	return c
}

func newDBFindCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "find <id>",
		Short: "Find advisories by PrimaryID or alias (CVE, GHSA, PYSEC, ...)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDriver(cmd)
			if err != nil {
				return err
			}
			defer d.Close()
			recs, err := d.Find(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printAdvisories(cmd, recs)
		},
	}
}

func newDBGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <cve-id>",
		Short: "Get the single advisory for one ID (errors if the ID resolves to several)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDriver(cmd)
			if err != nil {
				return err
			}
			defer d.Close()
			recs, err := d.Find(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if len(recs) > 1 {
				ids := make([]string, len(recs))
				for i, r := range recs {
					ids[i] = r.PrimaryID
				}
				return fmt.Errorf("%q resolves to %d advisories (%v); use `wisteria db find`", args[0], len(recs), ids)
			}
			return printAdvisories(cmd, recs)
		},
	}
}

func newDBPackageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "package <ecosystem> <name>",
		Short: "Find advisories affecting one package (exact OSV ecosystem + name)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := openDriver(cmd)
			if err != nil {
				return err
			}
			defer d.Close()
			recs, err := d.FindByPackage(cmd.Context(), advisory.Ecosystem(args[0]), args[1])
			if err != nil {
				return err
			}
			if len(recs) == 0 {
				return fmt.Errorf("no advisories for (%s, %s)", args[0], args[1])
			}
			return printAdvisories(cmd, recs)
		},
	}
}

// openDriver resolves the DSN (explicit --dsn, else the local unified
// tree under the resolved cache dir) and opens it via the registry.
func openDriver(cmd *cobra.Command) (db.Driver, error) {
	dsn, _ := cmd.Flags().GetString(dsnFlag)
	if dsn == "" {
		cacheDirOverride, _ := cmd.Flags().GetString(cacheDirFlag)
		root, err := cachedir.Root(cacheDirOverride)
		if err != nil {
			return nil, err
		}
		dsn = "fs://" + filepath.Join(root, "unified")
	}
	d, err := db.Open(cmd.Context(), dsn)
	if err != nil && errors.Is(err, db.ErrUnknownScheme) {
		return nil, fmt.Errorf("%w (known schemes: fs)", err)
	}
	return d, err
}

// printAdvisories writes each record as one indented JSON object — a
// jq-friendly stream that stays the same shape for one or many hits.
func printAdvisories(cmd *cobra.Command, recs []advisory.UnifiedAdvisory) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	for _, rec := range recs {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}
