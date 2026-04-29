package annotator

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/internal/unified"
	nucleipkg "github.com/masahiro331/wisteria/internal/unified/nuclei"
	"github.com/masahiro331/wisteria/internal/unified/writer"
)

// nucleiSourceDir is the on-disk subtree the nuclei fetcher writes to,
// relative to <sourcesRoot>. The fetcher extracts the upstream archive
// in place, so the templates live one level deeper under the archive's
// own root directory.
const (
	nucleiSourceDir   = "nuclei"
	nucleiArchiveRoot = "nuclei-templates-main"
)

// AnnotateNuclei walks <sourcesRoot>/nuclei/nuclei-templates-main/ for
// projectdiscovery/nuclei-templates YAML files and, for every CVE-ID
// claimed by a template's info.classification.cve-id, sets
// UnifiedAdvisory.NucleiTemplates and rewrites the file under
// <outDir>/cve/<year>/.
//
// Templates without a CVE-ID classification are skipped during the
// walk (no join key). One template fans out to N CVE-IDs when
// classification.cve-id is a list.
//
// Within each CVE-ID bucket, templates appear in walk order
// (lexicographic path order) so the result is deterministic across
// reruns.
//
// Missing target → skip; missing tree → no-op (same policy as KEV /
// EPSS / ExploitDB so a partial pipeline run still works); malformed
// YAML → abort with the file path.
func AnnotateNuclei(ctx context.Context, sourcesRoot, outDir string) error {
	treeRoot := filepath.Join(sourcesRoot, nucleiSourceDir, nucleiArchiveRoot)
	if _, err := os.Stat(treeRoot); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("annotator: stat %s: %w", treeRoot, err)
	}

	templates, err := nucleipkg.Walk(ctx, treeRoot)
	if err != nil {
		return fmt.Errorf("annotator: walk nuclei: %w", err)
	}

	groups := groupNucleiByCVE(templates)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.NumCPU() * 4)
	for cve, tpls := range groups {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			return applyNucleiGroup(outDir, cve, tpls)
		})
	}
	return g.Wait()
}

// groupNucleiByCVE buckets templates by CVE-ID, preserving walk order
// inside each bucket. A template that classifies N CVE-IDs is placed
// into all N buckets — same shape as exploitdb's "one row, many CVEs"
// fan-out.
func groupNucleiByCVE(templates []nucleipkg.Template) map[string][]nucleipkg.Template {
	out := make(map[string][]nucleipkg.Template)
	for _, tpl := range templates {
		for _, cve := range tpl.Info.Classification.CVEID {
			out[cve] = append(out[cve], tpl)
		}
	}
	return out
}

// applyNucleiGroup resolves the unified file for one CVE-ID and, when
// present, attaches all matching templates. Missing target is a silent
// skip — see package doc.
func applyNucleiGroup(outDir, cveID string, tpls []nucleipkg.Template) error {
	path, ok := writer.CVEPath(outDir, cveID)
	if !ok {
		return nil
	}
	rec, ok, err := readUnified(path)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	rec.NucleiTemplates = make([]unified.NucleiTemplate, 0, len(tpls))
	for _, tpl := range tpls {
		rec.NucleiTemplates = append(rec.NucleiTemplates, nucleiTemplateRecord(tpl))
	}
	return writeUnified(path, rec)
}

// nucleiTemplateRecord copies one upstream Nuclei template into the
// unified shape. Provenance.Path is rooted under <sourcesRoot>
// (matching the convention used by other annotators) so a debug tool
// can resolve it back to the YAML file. Provenance.ID uses the
// template's `id` field, which is unique inside the upstream catalog.
func nucleiTemplateRecord(tpl nucleipkg.Template) unified.NucleiTemplate {
	return unified.NucleiTemplate{
		From: unified.Provenance{
			Kind: unified.SourceNuclei,
			Path: filepath.Join(nucleiSourceDir, nucleiArchiveRoot, tpl.Path),
			ID:   tpl.ID,
		},
		ID:         tpl.ID,
		Name:       tpl.Info.Name,
		Severity:   tpl.Info.Severity,
		Tags:       []string(tpl.Info.Tags),
		References: []string(tpl.Info.Reference),
	}
}
