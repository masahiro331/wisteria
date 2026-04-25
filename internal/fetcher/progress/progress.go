// Package progress wraps mpb to render download progress bars with size,
// percentage, transfer rate, and ETA.
package progress

import (
	"io"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// Tracker manages a group of progress bars rendered to a single writer.
// A nil Tracker is valid and silently no-ops every method, so callers can
// pass it unconditionally and skip wiring when progress UI is undesired
// (for example, in tests).
type Tracker struct {
	p *mpb.Progress
}

// New creates a Tracker that renders to out.
func New(out io.Writer) *Tracker {
	return &Tracker{p: mpb.New(mpb.WithOutput(out))}
}

// Bar adds a new progress bar. If total <= 0 the content size is unknown
// (for example, when the upstream uses chunked transfer encoding); in that
// case the bar shows the byte count and transfer rate but omits a
// percentage and ETA, since neither can be computed.
func (t *Tracker) Bar(name string, total int64) *Bar {
	if t == nil {
		return nil
	}
	if total > 0 {
		return &Bar{bar: t.knownSizeBar(name, total)}
	}
	return &Bar{bar: t.unknownSizeBar(name)}
}

func (t *Tracker) knownSizeBar(name string, total int64) *mpb.Bar {
	return t.p.AddBar(total,
		mpb.PrependDecorators(
			decor.Name(name+" "),
			decor.CountersKibiByte("% .2f / % .2f"),
		),
		mpb.AppendDecorators(
			decor.Percentage(decor.WC{W: 5}),
			decor.Name(" "),
			decor.EwmaETA(decor.ET_STYLE_GO, 60, decor.WC{W: 8}),
		),
	)
}

func (t *Tracker) unknownSizeBar(name string) *mpb.Bar {
	return t.p.New(0,
		mpb.SpinnerStyle(),
		mpb.PrependDecorators(
			decor.Name(name+" "),
			decor.CurrentKibiByte("% .2f"),
		),
		mpb.AppendDecorators(
			decor.Name(" "),
			decor.AverageSpeed(decor.SizeB1024(0), "% .2f/s", decor.WC{W: 12}),
		),
	)
}

// Wait blocks until every bar attached to the tracker has completed.
func (t *Tracker) Wait() {
	if t == nil {
		return
	}
	t.p.Wait()
}

// Bar tracks a single download.
type Bar struct {
	bar *mpb.Bar
}

// ProxyReader wraps r so reads advance the bar. If b is nil the original
// reader is returned unchanged. When wrapping a bar with unknown total,
// the reader is also marked complete on EOF so Wait() returns promptly.
func (b *Bar) ProxyReader(r io.Reader) io.ReadCloser {
	if b == nil {
		if rc, ok := r.(io.ReadCloser); ok {
			return rc
		}
		return io.NopCloser(r)
	}
	return &eofCompleter{ReadCloser: b.bar.ProxyReader(r), bar: b.bar}
}

// eofCompleter marks an unknown-total bar complete when the underlying
// reader returns io.EOF, so Wait() doesn't block forever waiting for the
// (never-reached) total.
type eofCompleter struct {
	io.ReadCloser
	bar  *mpb.Bar
	done bool
}

func (e *eofCompleter) Read(p []byte) (int, error) {
	n, err := e.ReadCloser.Read(p)
	if err == io.EOF && !e.done {
		e.done = true
		e.bar.SetTotal(-1, true)
	}
	return n, err
}
