package walker_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/masahiro331/wisteria/internal/unified/walker"
)

// TestIndex_ParallelMatchesSequential checks that fanning out OSV body
// parsing keeps the index identical to the sequential baseline. The
// fixture is fat enough that the worker pool actually overlaps work
// (multiple files per ecosystem, multiple ecosystems).
func TestIndex_ParallelMatchesSequential(t *testing.T) {
	root := t.TempDir()
	for eco, n := range map[string]int{"PyPI": 50, "npm": 50, "Go": 50} {
		for i := range n {
			rel := fmt.Sprintf("osv/%s/PKG-%04d.json", eco, i)
			body := fmt.Sprintf(`{"id":"PKG-%s-%04d","aliases":["CVE-2024-%04d"]}`, eco, i, i)
			writeFile(t, root, rel, body)
		}
	}

	seq, err := walker.Index(context.Background(), root, walker.WithConcurrency(1))
	if err != nil {
		t.Fatalf("Index seq: %v", err)
	}
	par, err := walker.Index(context.Background(), root, walker.WithConcurrency(16))
	if err != nil {
		t.Fatalf("Index par: %v", err)
	}

	if !reflect.DeepEqual(seq, par) {
		t.Fatalf("parallel result diverges from sequential\nseq keys=%d par keys=%d", len(seq), len(par))
	}
}

// TestIndex_ParallelStillFailsOnMalformed ensures fan-out doesn't swallow
// parse errors: one bad file still aborts the whole walk.
func TestIndex_ParallelStillFailsOnMalformed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "osv/PyPI/good.json", `{"id":"PYSEC-2024-1"}`)
	writeFile(t, root, "osv/PyPI/bad.json", `{not json`)

	_, err := walker.Index(context.Background(), root, walker.WithConcurrency(8))
	if err == nil {
		t.Fatal("expected error from malformed OSV file under parallel walk")
	}
}
