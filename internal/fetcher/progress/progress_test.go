package progress

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

// TestTracker_Wait_ReturnsForKnownSizeBar exercises the happy path where
// total is known and the bar completes naturally on EOF.
func TestTracker_Wait_ReturnsForKnownSizeBar(t *testing.T) {
	tr := New(io.Discard)
	const payload = "hello world"
	bar := tr.Bar("known", int64(len(payload)))

	r := bar.ProxyReader(strings.NewReader(payload))
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	r.Close()

	waitInTime(t, tr, 2*time.Second)
}

// TestTracker_Wait_ReturnsForUnknownSizeBar guards against the bug where
// total = -1 causes mpb.Progress.Wait() to block forever because the bar
// never reports completion. The fix is to mark the bar complete on EOF.
func TestTracker_Wait_ReturnsForUnknownSizeBar(t *testing.T) {
	tr := New(io.Discard)
	bar := tr.Bar("unknown", -1)

	r := bar.ProxyReader(bytes.NewReader([]byte("payload")))
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	r.Close()

	waitInTime(t, tr, 2*time.Second)
}

// TestNilTracker_IsSafe ensures every method is callable on a nil Tracker
// without panicking and without doing any I/O.
func TestNilTracker_IsSafe(t *testing.T) {
	var tr *Tracker
	bar := tr.Bar("noop", -1)
	rc := bar.ProxyReader(strings.NewReader("data"))
	if _, err := io.Copy(io.Discard, rc); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	rc.Close()
	tr.Wait()
}

func waitInTime(t *testing.T, tr *Tracker, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		tr.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("Tracker.Wait() did not return within %s — bar likely never marked complete", d)
	}
}
