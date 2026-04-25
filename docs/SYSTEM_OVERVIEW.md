# System Overview

## Product

**Wisteria** is a free, fast vulnerability database builder. It is a Go CLI that:

1. Aggregates vulnerability data from public sources (OSV, MITRE CVEListV5).
2. (Future) Enriches each record with AI-generated summaries, labels, and
   exploit analysis using a mix of the Claude API and a local LLM.
3. (Future) Stores the unified, enriched data in PostgreSQL with a stable
   product identifier scheme.

The goal is to provide a vulnerability database that does not depend on a
commercial vendor.

## Phases

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Download upstream sources to local files under `~/.cache/wisteria/` | In progress |
| 2 | AI processing (Claude API + local LLM) — summaries, labels, exploit analysis | Not started |
| 3 | PostgreSQL storage and product identifier design | Not started |

## CLI

```
wisteria fetch osv
wisteria fetch cve
wisteria fetch all
```

Common flags (see `wisteria fetch --help` for the full list):
- `--cache-dir` — override the on-disk root.
- `--concurrency` — cap parallel downloads (OSV; default 4).
- `--retries` — HTTP retry attempts (default 3).

## On-disk layout

Default root: `os.UserCacheDir()/wisteria` (override via `--cache-dir`,
`WISTERIA_CACHE_DIR`, or fall back to OS default).

```
~/.cache/wisteria/
├── osv/
│   └── <ecosystem>/        ← unzipped per-ecosystem JSON files
└── cve/
    └── cvelistV5-main/     ← extracted MITRE archive
```

Archives (`.zip`, `.tar.gz`) are removed after extraction.

## Architecture

- `main.go` — entrypoint; wires a signal-aware context into Cobra.
- `cmd/` — CLI surface. `fetch` subcommands (`osv`, `cve`, `all`) drive the
  fetchers via the shared `fetcher.Fetcher` interface.
- `internal/fetcher/` — source integrations.
  - `fetcher.go` — `Fetcher` interface (`Name()`, `Fetch(ctx) (dir, error)`).
    New sources implement this so `cmd/fetch` stays uniform.
  - `osv/` — OSV per-ecosystem fetcher. Reads `ecosystems.txt`, then
    downloads each `{ecosystem}/all.zip` in parallel via `errgroup` with a
    configurable cap; the first error cancels in-flight siblings.
  - `cve/` — MITRE CVEListV5 fetcher. Downloads the repo tarball, extracts
    it, and removes the tarball.
  - `progress/` — fetcher-side progress UI; thin `mpb` wrapper used by
    fetchers and `cmd/fetch`.
- `internal/x/` — cross-cutting utilities.
  - `archive/` — `Zip` and `TarGz` extractors; both reject zip-slip /
    tar-slip entries.
  - `cachedir/` — resolves and creates per-source on-disk directories.
    Path resolution only — there is no eviction or in-memory cache layer.
  - `http/` (package `xhttp`) — `DoWithRetry` wraps `http.Client.Do` with
    exponential backoff + jitter. Retries transport errors and 5xx; 4xx
    are returned as-is.

### Testing seams

Fetchers expose `WithBaseURL` / `WithArchiveURL` and `WithHTTPClient`
options so tests can inject `httptest.Server`. Tests override `HOME` and
`XDG_CACHE_HOME` to redirect cache writes into `t.TempDir()`.

## Vulnerability DB requirements (target shape)

Per the project design meeting (`docs/meetings/2026-04-25-project-design.md`),
each record will eventually carry:

0. A unique identifier for the affected product (deterministic name
   resolution, AI-assisted where needed).
1. Product overview summary (AI, multi-source).
2. Vulnerability identifier (deterministic).
3. Vulnerability summary (AI, multi-source) including chainable exploit
   types.
4. Vulnerability references (deterministic).
5. Exploit-code existence (deterministic) plus AI judgment on
   exploitability or the cost of developing an exploit.
6. EPSS / CVSS / attack vector (deterministic).
7. Vulnerability labeling such as XSS or prototype pollution (AI).
8. In-the-wild signal — "social temperature".

Phase 1 only covers items 2, 4, and 6 (data still in raw upstream form);
items 0, 1, 3, 5, 7, 8 land in Phases 2–3.
