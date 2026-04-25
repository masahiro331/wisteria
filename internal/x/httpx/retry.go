// Package httpx contains small HTTP utilities shared by fetchers.
package httpx

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// RetryOptions controls DoWithRetry. Zero values fall back to defaults
// (3 attempts, 500ms base, 5s cap).
type RetryOptions struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
}

const (
	defaultAttempts = 3
	defaultBase     = 500 * time.Millisecond
	defaultMax      = 5 * time.Second
)

func (o RetryOptions) normalize() RetryOptions {
	if o.Attempts <= 0 {
		o.Attempts = defaultAttempts
	}
	if o.Base <= 0 {
		o.Base = defaultBase
	}
	if o.Max <= 0 {
		o.Max = defaultMax
	}
	return o
}

// DoWithRetry runs client.Do up to opts.Attempts times. It retries on
// transport errors and 5xx responses; 4xx responses are returned to the
// caller without further retries (they are not transient). Intermediate
// response bodies are drained and closed so the underlying connection
// can be reused.
//
// Backoff is exponential with full jitter, capped at opts.Max. Context
// cancellation aborts any in-progress wait and is returned as the error.
func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request, opts RetryOptions) (*http.Response, error) {
	opts = opts.normalize()

	var lastErr error
	for attempt := 0; attempt < opts.Attempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoff(attempt, opts.Base, opts.Max)); err != nil {
				return nil, err
			}
		}
		// Clone so the original request stays reusable across retries even
		// if the transport mutates state (e.g. sets Host).
		resp, err := client.Do(req.Clone(ctx))
		if err != nil {
			lastErr = err
			continue
		}
		// On the final attempt, return whatever we got (including 5xx) so
		// the caller can inspect the failure response.
		if resp.StatusCode < 500 || attempt == opts.Attempts-1 {
			return resp, nil
		}
		// Transient 5xx mid-loop: drain and try again so the connection
		// can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = nil
	}
	return nil, lastErr
}

func backoff(attempt int, base, ceiling time.Duration) time.Duration {
	d := base << (attempt - 1) // 2^(attempt-1) * base
	if d <= 0 || d > ceiling {
		d = ceiling
	}
	// Full jitter: random in [0, d].
	return time.Duration(rand.Int64N(int64(d) + 1))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
