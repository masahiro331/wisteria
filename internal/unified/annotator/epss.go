package annotator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/internal/unified/epss"
	"github.com/masahiro331/wisteria/pkg/advisory"
)

const epssCatalogRelPath = "epss/epss_scores-current.csv"

// AnnotateEPSS reads <sourcesRoot>/epss/epss_scores-current.csv and,
// for every score whose CVE-ID has a matching unified file under
// <outDir>/cve/<year>/, sets UnifiedAdvisory.EPSS and rewrites the file.
//
// EPSS catalogs are O(100k) rows, so per-score apply runs in parallel
// (errgroup with 4× NumCPU). Each row keys a different CVE-ID, so two
// goroutines never write the same file. Missing target → skip; missing
// catalog → no-op; malformed row → abort.
func AnnotateEPSS(ctx context.Context, sourcesRoot, outDir string) error {
	catalogPath := filepath.Join(sourcesRoot, epssCatalogRelPath)
	f, err := os.Open(catalogPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("annotator: open %s: %w", catalogPath, err)
	}
	defer f.Close()

	cat, err := epss.Read(f)
	if err != nil {
		return fmt.Errorf("annotator: parse %s: %w", catalogPath, err)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.NumCPU() * 4)
	for _, score := range cat.Scores {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			return applyEPSSScore(outDir, cat.ModelVersion, cat.ScoreDate, score)
		})
	}
	return g.Wait()
}

// applyEPSSScore resolves the unified file for one EPSS score and, when
// present, merges the score into it. Missing target is a silent skip.
func applyEPSSScore(outDir, modelVersion, scoreDate string, s epss.Score) error {
	return updateCVE(outDir, s.CVE, func(rec *advisory.UnifiedAdvisory) {
		rec.EPSS = &advisory.EPSSScore{
			From: advisory.Provenance{
				Kind: advisory.SourceEPSS,
				Path: epssCatalogRelPath,
				ID:   s.CVE,
			},
			Score:        s.EPSS,
			Percentile:   s.Percentile,
			ScoreDate:    scoreDate,
			ModelVersion: modelVersion,
		}
	})
}
