// Package xhttp contains small HTTP utilities shared by fetchers.
package xhttp

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// RetryOptions controls DoWithRetry. Zero values fall back to defaults
// (3 attempts, 500ms base, 5s cap; 1m rate-limit wait, 5m rate-limit cap).
type RetryOptions struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
	// RateLimitWait is the wait before retrying a 429 that carries no usable
	// Retry-After. It doubles per attempt up to RateLimitMax.
	RateLimitWait time.Duration
	// RateLimitMax caps the wait before retrying a 429, Retry-After included.
	RateLimitMax time.Duration
}

const (
	defaultAttempts      = 3
	defaultBase          = 500 * time.Millisecond
	defaultMax           = 5 * time.Second
	defaultRateLimitWait = time.Minute
	defaultRateLimitMax  = 5 * time.Minute
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
	if o.RateLimitWait <= 0 {
		o.RateLimitWait = defaultRateLimitWait
	}
	if o.RateLimitMax <= 0 {
		o.RateLimitMax = defaultRateLimitMax
	}
	return o
}

// DoWithRetry runs client.Do up to opts.Attempts times. It retries on
// transport errors, 5xx responses and 429 Too Many Requests; other 4xx
// responses are returned to the caller without further retries (they are
// not transient). Intermediate response bodies are drained and closed so
// the underlying connection can be reused.
//
// Backoff is exponential with full jitter, capped at opts.Max. A 429 waits
// longer instead (see rateLimitDelay), because rate limits such as GitHub's
// lift after minutes, not seconds. Context cancellation aborts any
// in-progress wait and is returned as the error.
func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request, opts RetryOptions) (*http.Response, error) {
	opts = opts.normalize()

	var lastErr error
	var wait time.Duration
	for attempt := 0; attempt < opts.Attempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		// Clone so the original request stays reusable across retries even
		// if the transport mutates state (e.g. sets Host).
		resp, err := client.Do(req.Clone(ctx))
		if err != nil {
			lastErr = err
			wait = backoff(attempt+1, opts.Base, opts.Max)
			continue
		}
		rateLimited := resp.StatusCode == http.StatusTooManyRequests
		// On the final attempt, return whatever we got (including 5xx and
		// 429) so the caller can inspect the failure response.
		if (resp.StatusCode < 500 && !rateLimited) || attempt == opts.Attempts-1 {
			return resp, nil
		}
		if rateLimited {
			wait = rateLimitDelay(resp.Header.Get("Retry-After"), attempt+1, opts, time.Now())
		} else {
			wait = backoff(attempt+1, opts.Base, opts.Max)
		}
		// Transient 5xx / 429 mid-loop: drain and try again so the
		// connection can be reused.
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

// rateLimitDelay returns the wait before retry number attempt (1-based)
// after a 429. A Retry-After of delay-seconds or an HTTP date wins;
// without a usable one the wait is opts.RateLimitWait doubled per attempt.
// Either way it is capped at opts.RateLimitMax. opts must be normalized.
func rateLimitDelay(retryAfter string, attempt int, opts RetryOptions, now time.Time) time.Duration {
	d := opts.RateLimitWait << (attempt - 1)
	if d <= 0 || d > opts.RateLimitMax {
		d = opts.RateLimitMax
	}
	if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
		// Compare in seconds first so a huge header cannot overflow.
		d = opts.RateLimitMax
		if int64(secs) < int64(opts.RateLimitMax/time.Second) {
			d = time.Duration(secs) * time.Second
		}
	} else if t, err := http.ParseTime(retryAfter); err == nil && t.After(now) {
		d = t.Sub(now)
	}
	return min(d, opts.RateLimitMax)
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
