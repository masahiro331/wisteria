package annotator

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/masahiro331/wisteria/pkg/advisory"
)

// AnnotateFixCommits derives the vulnerability-fixing commit(s) for every CVE
// under <outDir>/cve/ and sets UnifiedAdvisory.FixCommits.
//
// This is the deterministic VFC layer: it only structures fix commits the
// advisory already states — an OSV GIT range's fixed event, or a GitHub commit
// URL among the references. It reads no external catalog and makes no network
// call, so it costs nothing beyond the file pass and cannot be wrong about a
// commit it did not invent. Deriving a commit for advisories that link none
// (version-range search, ranking) is a separate, online, opt-in step.
//
// Unlike the KEV / EPSS / ExploitDB annotators — which join an external catalog
// by CVE-ID — this one's input is each record's own content, so it walks the
// cve/ tree rather than iterating a catalog. A missing cve/ tree is a no-op.
func AnnotateFixCommits(ctx context.Context, _, outDir string) error {
	root := filepath.Join(outDir, "cve")
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.NumCPU() * 4)

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A missing cve/ tree (partial pipeline) is not an error.
			if _, statErr := filepath.Abs(path); statErr == nil && path == root {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			return applyFixCommits(path)
		})
		return nil
	})
	if walkErr != nil {
		// SkipDir at the root or a vanished tree: let the group finish and
		// report its own error, if any. Any other walk error propagates.
		if !isMissingTree(walkErr) {
			_ = g.Wait()
			return walkErr
		}
	}
	return g.Wait()
}

func isMissingTree(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "no such file") || err == filepath.SkipDir)
}

func applyFixCommits(path string) error {
	rec, ok, err := readUnified(path)
	if err != nil || !ok {
		return err
	}
	fixes := DeriveFixCommits(&rec)
	if len(fixes) == 0 {
		return nil // nothing to add; leave the file untouched
	}
	rec.FixCommits = fixes
	return writeUnified(path, rec)
}

// DeriveFixCommits extracts fix commits from a record's own OSV GIT ranges and
// GitHub commit references, deduplicated by (repo, sha). It is pure: no I/O, no
// network — the whole VFC-deterministic policy lives here so it can be tested in
// isolation and reused by other tools.
func DeriveFixCommits(rec *advisory.UnifiedAdvisory) []advisory.FixCommit {
	seen := map[string]bool{}
	var out []advisory.FixCommit

	add := func(fc advisory.FixCommit) {
		key := fc.Repo + "@" + fc.SHA
		if fc.SHA == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fc)
	}

	// (a) OSV GIT ranges: events[].fixed on a GIT-typed range.
	for _, a := range rec.Affected {
		if a.OSV == nil {
			continue
		}
		for _, rg := range gitRanges(a.OSV) {
			repo := normalizeRepo(rg.Repo)
			for _, e := range rg.Events {
				if e.Fixed == "" {
					continue
				}
				add(advisory.FixCommit{
					From: advisory.Provenance{Kind: advisory.SourceOSV, Path: rg.Repo, ID: e.Fixed},
					Repo: repo,
					SHA:  strings.ToLower(e.Fixed),
					URL:  commitURL(repo, e.Fixed),
				})
			}
		}
	}

	// (b) GitHub commit URLs among the references.
	for _, ref := range rec.References {
		if repo, sha, ok := parseCommitURL(ref.URL); ok {
			add(advisory.FixCommit{
				From: advisory.Provenance{Kind: advisory.SourceCVE, Path: ref.URL, ID: sha},
				Repo: repo,
				SHA:  sha,
				URL:  ref.URL,
			})
		}
	}
	return out
}

type gitRange struct {
	Type   string `json:"type"`
	Repo   string `json:"repo"`
	Events []struct {
		Fixed string `json:"fixed"`
	} `json:"events"`
}

// gitRanges pulls GIT-typed ranges out of an OSV affected block. The block is
// stored as `any` (each ecosystem has its own concrete shape), so a marshal /
// unmarshal round-trip is the shape-agnostic way to reach ranges[].
func gitRanges(osv any) []gitRange {
	b, err := json.Marshal(osv)
	if err != nil {
		return nil
	}
	var wrap struct {
		Ranges []gitRange `json:"ranges"`
	}
	if json.Unmarshal(b, &wrap) != nil {
		return nil
	}
	var out []gitRange
	for _, rg := range wrap.Ranges {
		if strings.EqualFold(rg.Type, "GIT") {
			out = append(out, rg)
		}
	}
	return out
}

var commitRe = regexp.MustCompile(`(?i)^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/commits?/([0-9a-f]{7,40})/?$`)

func parseCommitURL(u string) (repo, sha string, ok bool) {
	m := commitRe.FindStringSubmatch(strings.TrimSpace(u))
	if m == nil {
		return "", "", false
	}
	return m[1] + "/" + m[2], strings.ToLower(m[3]), true
}

// normalizeRepo turns an OSV GIT range repo URL into "owner/name" when it is a
// GitHub URL; otherwise it returns the URL unchanged (a non-GitHub host has no
// owner/name form and stays a plain repo string).
func normalizeRepo(repoURL string) string {
	s := strings.TrimSuffix(repoURL, ".git")
	for _, pfx := range []string{"https://github.com/", "http://github.com/"} {
		if strings.HasPrefix(s, pfx) {
			return strings.TrimSuffix(strings.TrimPrefix(s, pfx), "/")
		}
	}
	return repoURL
}

func commitURL(repo, sha string) string {
	if strings.Contains(repo, "/") && !strings.Contains(repo, "://") {
		return "https://github.com/" + repo + "/commit/" + sha
	}
	return ""
}
