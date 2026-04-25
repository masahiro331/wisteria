package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/masahiro331/wisteria/internal/fetcher/progress"
)

// WriteResponse copies resp.Body into a file at dest, advancing bar as
// bytes flow. The whole pipeline (proxy reader → file write → close)
// is wrapped so an error at any step propagates with dest in context.
//
// Used by single-file fetchers (osv, cve, kev) that just persist the
// upstream payload as-is. Sources that need stream transformation
// (e.g. epss decompresses gzip and writes atomically via temp+rename)
// implement their own write step.
func WriteResponse(dest string, resp *http.Response, bar *progress.Bar) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	body := bar.ProxyReader(resp.Body)
	if _, err := io.Copy(out, body); err != nil {
		_ = body.Close()
		_ = out.Close()
		return fmt.Errorf("write %s: %w", dest, err)
	}
	if err := body.Close(); err != nil {
		_ = out.Close()
		return fmt.Errorf("close body: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dest, err)
	}
	return nil
}
