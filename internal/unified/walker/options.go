package walker

import (
	"io"
	"runtime"
)

// Option configures the Index walk. Defaults are chosen so the zero-arg
// call site (`walker.Index(ctx, root)`) keeps existing behavior modulo
// parallel OSV body parsing.
type Option func(*config)

type config struct {
	// concurrency caps the number of OSV files parsed in parallel. CVE5
	// is filename-only and not parallelized — the bottleneck Index used
	// to have was OSV body unmarshal, so the knob targets just that.
	concurrency int
	// warnLog receives one line per file the walk skipped because it
	// became inaccessible (endpoint-protection quarantine, vanish). nil
	// means skip silently.
	warnLog io.Writer
}

// WithConcurrency sets the OSV-parse worker pool size. Values <= 0 fall
// back to defaultConcurrency. The walk itself (filepath.WalkDir) stays
// single-threaded; this only fans out per-file ReadFile + json.Unmarshal.
func WithConcurrency(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.concurrency = n
		}
	}
}

// WithWarnLog sets the destination for skip warnings. The walk skips
// (instead of aborting on) OSV files that turn out to be unreadable for
// environmental reasons — EPERM/EACCES from an endpoint-protection
// quarantine of malicious-PoC advisories (MAL-* records), or the file
// vanishing between WalkDir and the read. A nil writer skips silently.
func WithWarnLog(w io.Writer) Option {
	return func(c *config) { c.warnLog = w }
}

func defaultConcurrency() int {
	// I/O-bound work: 4× CPU is the empirical sweet spot from `wisteria
	// fetch osv` and matches the per-stage default agreed for Stage 2/3.
	return runtime.NumCPU() * 4
}

func newConfig(opts []Option) config {
	c := config{concurrency: defaultConcurrency()}
	for _, o := range opts {
		o(&c)
	}
	if c.concurrency <= 0 {
		c.concurrency = 1
	}
	return c
}
