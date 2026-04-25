# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Wisteria is a free, fast vulnerability database builder. It is a Go CLI that aggregates data from public sources (OSV, MITRE CVEListV5, CISA KEV, FIRST EPSS) and — across later phases — enriches it with AI-generated summaries and stores everything in PostgreSQL.

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
- `cmd/` — Cobra command tree. `fetch` subcommands (`osv`, `cve`, `kev`, `epss`, `all`) delegate to fetchers via the `fetcher.Fetcher` interface.
- `internal/fetcher/fetcher.go` — defines the `Fetcher` interface (`Name()`, `Fetch(ctx) (dir, error)`). New sources implement this interface so commands can treat them uniformly.
- `internal/fetcher/osv/` — OSV fetcher; reads `ecosystems.txt` then downloads each `{ecosystem}/all.zip`. Downloads run in parallel via `errgroup` with a configurable cap (`--concurrency`, default 4); the first error cancels in-flight siblings. Each archive is unzipped in place and removed.
- `internal/fetcher/cve/` — MITRE CVEListV5 fetcher; downloads the repo tarball, extracts it, and removes the tarball.
- `internal/fetcher/kev/` — CISA Known Exploited Vulnerabilities fetcher; downloads `known_exploited_vulnerabilities.json` (single file, no archive).
- `internal/fetcher/epss/` — FIRST EPSS daily score fetcher; downloads `epss_scores-current.csv.gz` and decompresses it on the fly so downstream stages get a plain CSV.
- `internal/fetcher/progress/` — fetcher-side progress UI; thin mpb wrapper used by fetchers and `cmd/fetch`.
- `internal/unified/{osv,cve,kev,epss}/` — parser-side schema types for upstream catalog formats. Field names follow the upstream JSON / CSV verbatim. **Every upstream field is declared as a typed Go field so a parse + re-marshal round-trip preserves all keys** (the design's "1 byte not lost" rule, §7); free-form per-source blobs (`database_specific`, `ecosystem_specific`, `Metric.Other.Content`, `x_*`) are kept as `json.RawMessage`. KEV `dateAdded` / `dueDate` use a `Date` wrapper that parses `YYYY-MM-DD`. EPSS exposes a `Read(r io.Reader)` that skips the leading `#` comment + CSV header and returns `[]Score`. UnifiedAdvisory and the rest of the pipeline live elsewhere (added by later issues).
- `debug/schema-coverage/` — dev-time script that walks `<root>` (default `tmp/sources`), parses each file twice (typed schema vs `interface{}`), and reports JSON paths the typed schema would drop. Run after editing any `internal/unified/{osv,cve,kev}` schema; expected output is `no missing fields detected` for all three. Not built into the production binary.
- `internal/x/archive/` — `Zip` and `TarGz` helpers; both reject zip-slip / tar-slip entries.
- `internal/x/http/` (package `xhttp`) — `DoWithRetry` wraps `http.Client.Do` with exponential backoff + jitter. Retries transport errors and 5xx; 4xx are returned as-is. Default 3 attempts (`--retries`).
- `internal/x/cachedir/` — resolves and creates per-source cache directories. Root precedence: explicit override (`--cache-dir`) → `WISTERIA_CACHE_DIR` env → `os.UserCacheDir()/wisteria`. Per-source dirs are placed under `<root>/sources/<source>/` so the unified pipeline can write into a sibling `<root>/unified/` subtree. Path-resolution only; not a cache layer with eviction.

Fetchers expose `WithBaseURL` (osv) / `WithArchiveURL` (cve) / `WithCatalogURL` (kev, epss) and `WithHTTPClient` options so tests can inject `httptest.Server`. Tests override `HOME` and `XDG_CACHE_HOME` to redirect cache writes into `t.TempDir()`.

## Conventions

- TDD: write a failing test first, then the implementation, then refactor. Run `make test` and `make fmt` before committing.
- Keep new source integrations behind the `Fetcher` interface so `cmd/fetch.go` stays uniform.
- Branch-per-feature PRs: do not commit directly to `main`. For each functional unit of work, create a dedicated branch and open a PR.
- No Claude attribution in git or GitHub artifacts: commit messages, PR titles, and PR bodies must not include `Co-Authored-By: Claude ...`, `🤖 Generated with [Claude Code]`, or any other Claude/Anthropic signature line. Enforced by the `commit-lint` workflow.

## Issue-driven workflow

Tasks live in **GitHub Issues**, not in design docs. Design docs in `docs/design/` describe decided design only — pipeline shape, types, merge rules, stage I/F. PR plans, deferred work, and open questions belong in Issues.

- Before starting any non-trivial unit of work, confirm there is an Issue for it. If not, propose one to the user (title + 1-2 line description) and create it via `gh issue create` only after approval.
- Each branch + PR resolves one Issue. PR description must include `Closes #N` so the Issue auto-closes on merge.
- Codex review findings that are not merge blockers should be filed as follow-up Issues (label `kind/codex-finding`) rather than left in commit messages or PR comments.
- Do not modify Issues, labels, milestones, or other shared GitHub state without explicit user approval per the "Executing actions with care" rules.

Labels in use:

- `phase/1-source-ingestion`, `phase/2-ai`, `phase/3-postgres` — which roadmap phase the work belongs to
- `kind/feature`, `kind/refactor`, `kind/open-question`, `kind/codex-finding` — what kind of work it is
- `priority/blocker` — apply only when the issue blocks other work; default is no priority label

Milestone `Unified Advisory pipeline` bundles the entire Stage 1-4 implementation. The milestone lives inside Phase 1 (source ingestion), not above it.

## Codex review

Use Codex as a second-opinion reviewer at two trigger points:

1. **Stuck in implementation.** If three consecutive attempts at the same fix fail to make `make test` pass, or a non-trivial design decision needs a sanity check, hand the situation to Codex via the `codex:codex-rescue` subagent. Surface Codex's diagnosis to the user before continuing.
2. **After a commit on any non-`main` branch passes `make test`.** Run a Codex review automatically right after the commit. Skip on `main`. Also skip when the commit is doc-only, formatting/cosmetic-only, or otherwise has no behavioral change (e.g. typo fix, comment rewording, gofmt-only). When in doubt, run the review.

Mechanics for trigger 2:

- Input: the full branch diff (`git diff main...HEAD`) plus all directly related design docs under `docs/design/`. If no design doc applies, say so explicitly when invoking Codex.
- Caller: `codex:codex-rescue` subagent.
- Disposition: relay every Codex finding to the user, preserving each finding's severity (High/Medium/Low), affected files/lines, and Codex's overall verdict verbatim. Claude may add its own recommendation per finding but must not drop, re-rank, or downgrade items based on its own judgment. Do not auto-apply fixes — the user decides whether to address each point in a follow-up commit.
