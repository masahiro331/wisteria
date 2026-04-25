package walker_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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
// parse errors: one bad file still aborts the whole walk and the
// returned error names the offending file (not just "context canceled",
// which is what the errgroup's cancel propagation produces internally).
func TestIndex_ParallelStillFailsOnMalformed(t *testing.T) {
	root := t.TempDir()
	// Many good files so the bad one likely lands mid-walk and the
	// errgroup's context cancellation reaches the WalkDir callback
	// before the walk naturally ends — which is when the bug masks
	// the worker error with context.Canceled.
	for i := range 200 {
		writeFile(t, root, fmt.Sprintf("osv/PyPI/good-%04d.json", i),
			fmt.Sprintf(`{"id":"PYSEC-2024-%04d"}`, i))
	}
	writeFile(t, root, "osv/PyPI/bad.json", `{not json`)

	_, err := walker.Index(context.Background(), root, walker.WithConcurrency(8))
	if err == nil {
		t.Fatal("expected error from malformed OSV file under parallel walk")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("error should be the parse error, not context.Canceled: %v", err)
	}
	if !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("error should name the offending file, got: %v", err)
	}
}
