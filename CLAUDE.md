# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Wisteria is a free, fast vulnerability database builder. It is a Go CLI that aggregates data from public sources (OSV, MITRE CVEListV5) and — across later phases — enriches it with AI-generated summaries and stores everything in PostgreSQL.

See `docs/meetings/2026-04-25-project-design.md` for the full requirements list and phase plan.

## Phases

- Phase 1 (current): download upstream sources to local files under `~/.cache/wisteria/`
- Phase 2: AI processing (Claude API + local LLM) for summaries, labeling, exploit analysis
- Phase 3: PostgreSQL storage and product identifier design

## Common commands

- `make test` — run all tests
- `make fmt` — gofmt -s -w
- `make vet` — go vet
- `make build` — build the `wisteria` binary
- `go test ./internal/fetcher/osv/...` — run a single package's tests

## Architecture

- `main.go` — entrypoint; wires signal-aware context into the root command.
- `cmd/` — Cobra command tree. `fetch` subcommands (`osv`, `cve`, `all`) delegate to fetchers via the `fetcher.Fetcher` interface.
- `internal/fetcher/fetcher.go` — defines the `Fetcher` interface (`Name()`, `Fetch(ctx) (dir, error)`). New sources implement this interface so commands can treat them uniformly.
- `internal/fetcher/osv/` — OSV fetcher; reads `ecosystems.txt` then downloads each `{ecosystem}/all.zip`. Downloads run in parallel via `errgroup` with a configurable cap (`--concurrency`, default 4); the first error cancels in-flight siblings.
- `internal/fetcher/cve/` — MITRE CVEListV5 fetcher; downloads the repo tarball.
- `internal/cache/` — resolves and creates per-source cache directories. Root precedence: explicit override (`--cache-dir`) → `WISTERIA_CACHE_DIR` env → `os.UserCacheDir()/wisteria`.

Fetchers expose `WithBaseURL` / `WithArchiveURL` and `WithHTTPClient` options so tests can inject `httptest.Server`. Tests override `HOME` and `XDG_CACHE_HOME` to redirect cache writes into `t.TempDir()`.

## Conventions

- TDD: write a failing test first, then the implementation, then refactor. Run `make test` and `make fmt` before committing.
- Keep new source integrations behind the `Fetcher` interface so `cmd/fetch.go` stays uniform.
