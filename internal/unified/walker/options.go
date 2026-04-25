package walker

import "runtime"

// Option configures the Index walk. Defaults are chosen so the zero-arg
// call site (`walker.Index(ctx, root)`) keeps existing behavior modulo
// parallel OSV body parsing.
type Option func(*config)

type config struct {
	// concurrency caps the number of OSV files parsed in parallel. CVE5
	// is filename-only and not parallelized — the bottleneck Index used
	// to have was OSV body unmarshal, so the knob targets just that.
	concurrency int
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
