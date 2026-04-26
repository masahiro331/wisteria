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
- `make build` — build the `wisteria` binary into `./bin/wisteria`
- `make clean` — remove the built binary (and the `./bin/` directory if it ends up empty)
- `go test ./internal/fetcher/osv/...` — run a single package's tests

## Architecture

- `main.go` — entrypoint; wires signal-aware context into the root command.
- `cmd/` — Cobra command tree. `fetch` subcommands (`osv`, `cve`, `kev`, `epss`, `exploitdb`, `all`) delegate to fetchers via the `fetcher.Fetcher` interface. `wisteria unify --cache-dir <path>` is a thin shell that owns only flag parsing + pprof and delegates to `pipeline.Run`. Memory resident is bounded by the worker pool (≈ `--concurrency` records in flight; default 4× NumCPU), not by total record count.
- `cmd/debug/` — `wisteria debug` parent + one-file-per-subcommand inspection helpers. `debug index` prints walker.Index distribution (PrimaryIDs total, per-Kind entry counts, entries-per-PrimaryID histogram, per-ecosystem OSV counts) or, with `--id`, lists the IndexEntry paths under one PrimaryID (exits non-zero if not found). `debug unify --id <PrimaryID>` runs Stage 1 walker + Stage 2 full merge for one PrimaryID and prints the resulting UnifiedAdvisory as JSON. `debug annotate` runs Stage 4 (KEV + EPSS + ExploitDB) against an existing `unified/` tree without rebuilding it from sources, by calling `annotator.RunAll` with an empty line prefix. `debug ai summarize` runs a Summarizer provider (currently Ollama) against one UnifiedAdvisory loaded by `--id` or `--from-stdin`. Subcommands inherit the persistent `--cache-dir` flag.
- `internal/unified/pipeline/` — Stage 1-4 orchestration extracted out of `cmd/unify`. `Run(ctx, cacheDir, opts, w)` resolves the cache root, runs `walker.Index` (Stage 1), `writer.Reset` + an `errgroup`-bounded `unifier.MergePrimary → writer.Write` fan-out (Stage 2+3), then `annotator.RunAll` (Stage 4) under a `"stage 4 "` line prefix. Concurrency defaults to 4× NumCPU when `Options.Concurrency == 0`. Per-stage timing is written to `w` (nil-safe). First error aborts the pipeline; Stage 2+3 errors carry the PrimaryID, Stage 4 errors carry the annotator name. cpuprofile is intentionally _not_ here — it is a CLI-only concern.
- `internal/fetcher/fetcher.go` — defines the `Fetcher` interface (`Name()`, `Fetch(ctx) (dir, error)`). New sources implement this interface so commands can treat them uniformly.
- `internal/fetcher/osv/` — OSV fetcher; reads `ecosystems.txt` then downloads each `{ecosystem}/all.zip`. Downloads run in parallel via `errgroup` with a configurable cap (`--concurrency`, default 4); the first error cancels in-flight siblings. Each archive is unzipped in place and removed.
- `internal/fetcher/cve/` — MITRE CVEListV5 fetcher; downloads the repo tarball, extracts it, and removes the tarball.
- `internal/fetcher/kev/` — CISA Known Exploited Vulnerabilities fetcher; downloads `known_exploited_vulnerabilities.json` (single file, no archive).
- `internal/fetcher/epss/` — FIRST EPSS daily score fetcher; downloads `epss_scores-current.csv.gz` and decompresses it on the fly so downstream stages get a plain CSV.
- `internal/fetcher/exploitdb/` — Exploit-DB fetcher; downloads `files_exploits.csv` (single file, no archive). Feeds the Stage 4 ExploitDB annotator.
- `internal/fetcher/progress/` — fetcher-side progress UI; thin mpb wrapper used by fetchers and `cmd/fetch`.
- `internal/unified/{osv,cve,kev,epss,exploitdb}/` — parser-side schema types for upstream catalog formats. Field names follow the upstream JSON / CSV verbatim. **Every upstream field is declared as a typed Go field so a parse + re-marshal round-trip preserves all keys** (the design's "1 byte not lost" rule, §7); free-form per-source blobs (`database_specific`, `ecosystem_specific`, `Metric.Other.Content`, `x_*`) are kept as `json.RawMessage`. KEV `dateAdded` / `dueDate` use a `Date` wrapper that parses `YYYY-MM-DD`. EPSS exposes a `Read(r io.Reader)` that consumes the leading `#model_version:..,score_date:..` comment into `Catalog.ModelVersion` / `Catalog.ScoreDate`, skips the CSV header, and returns the per-CVE rows as `[]Score`. ExploitDB parses `files_exploits.csv` (one row per exploit; multiple CVE-IDs per row land as separate `ExploitRecord` outputs).
- `internal/unified/unified.go` — pipeline core types defined by design §7: `SourceKind`, `Provenance`, `IndexEntry` (Stage 1 output), `Reference`, `Description`, `Severity`, `AffectedRecord`, `KEVRecord`, `EPSSScore`, and `UnifiedAdvisory` itself. Pure type declarations, no behavior — every stage subpackage depends on it.
- `internal/unified/unifier/` — Stage 2 of the unified-advisory pipeline. `MergePrimary(ctx, sourcesRoot, primaryID, entries)` is the only public entrypoint and produces one `UnifiedAdvisory` from one PrimaryID's IndexEntries. Stage-level orchestration (PrimaryID fan-out, error policy, writer hand-off) lives in `internal/unified/pipeline` so production can stream MergePrimary's output straight to disk. The merge uses pure helpers: `mergeReferences` (URL normalize + dedup + tag union + lex sort, §8.2), `mergeDescriptions` (parallel hold, sort by source priority → lang → input index, §8.3), `mergeSeverities` (priority-aware (Type,Vector) / (Type,Score) dedup with deterministic Vector → Score tie-breaker, §8.4), `mergeAffected` (parallel hold, sort by priority → Provenance.ID → input index, §8.5). The §8.3 / §8.4 / §8.5 sorts share `stableSortByPriority`, a generic helper that orders by (PriorityRank → caller-supplied `cmp.Compare`-style secondary → input index); only the secondary comparator differs per field. SourceIDs (every alias other than the PrimaryID, deduped + sorted) are collected inline during the per-entry parse loop — no second pass over the source files. CVE5 ADP containers (CISA Vulnrichment etc.) contribute their own Provenance with an `#adp:<shortName>` ID suffix, so CNA and ADP appear as parallel siblings. Vendor priority array is the §8.1 draft; final ordering + const-ification decided in #22. `PriorityRank` / `SourceTag` are exported so sibling packages (writer) can pick a primary Provenance among many.
- `internal/unified/writer/` — Stage 3. Public surface: `OutDir(cacheDir)` derives `<cacheDir>/unified` without touching the filesystem (read-only callers — annotator, debug tools — use this); `Init(cacheDir)` additionally validates the destination (non-empty, not `/`, outDir basename == `"unified"`, outDir is a regular directory or absent — symlinks / files refused) and clears the bucket-mkdir cache; `Reset(cacheDir)` is `Init` + `RemoveAll` + `MkdirAll` so `pipeline.Run` can start a fresh write fan-out in one call; `CVEPath(outDir, cveID)` returns the per-record routed path for a CVE-ID (used by annotators); `Write(outDir, rec)` serializes one `UnifiedAdvisory` to its bucket-derived path. The split between `Init` and `Reset` keeps per-record fan-out free of the one-shot tree reset. Bucket dirs (`unified/cve/<year>/`, `unified/standalone/<ecosystem>/`) are `MkdirAll`'d lazily and cached in a package-level `sync.Map` so 100k+ writes into the same bucket trigger one syscall, not N. CVE-IDs route to `cve/<year>/`; everything else routes to `standalone/<ecosystem>/` where `<ecosystem>` is the highest-priority OSV provenance under the record (via `unifier.PriorityRank`). The OSV provenance Path-derived ecosystem is normalized (`Red Hat` → `Red_Hat`) so it matches walker's `IndexEntry.Source` and the priority-table tags. PrimaryID `:` and `/` are escaped to `_`. Per-file atomic via temp + rename.
- `internal/unified/annotator/` — Stage 4. `AnnotateKEV` / `AnnotateEPSS` / `AnnotateExploitDB(ctx, sourcesRoot, outDir)` each read their respective catalog under `<sourcesRoot>/{kev,epss,exploitdb}/...`, then for each entry whose CVE-ID has a matching `<outDir>/cve/<year>/<CVE-ID>.json` file, set `UnifiedAdvisory.KEV` / `EPSS` / `Exploits` and rewrite the file in place (plain `os.WriteFile`; not atomic — Stage 4 reruns rebuild the file from upstream sources). EPSS apply runs in parallel via errgroup (4× NumCPU) since each row keys a different CVE-ID. Missing target → silent skip (signal-only handling deferred to #Q3). Missing catalog → no-op + nil error so partial pipelines (e.g. unify without `fetch kev`) work. Catalog parse failures abort with a file-naming error. `RunAll(ctx, sourcesRoot, outDir, w, linePrefix)` runs the three annotators in order (KEV → EPSS → ExploitDB) and writes per-stage timing to `w`; `pipeline.Run` passes `"stage 4 "` so timing lines align with the upstream "stage 1" / "stage 2+3" banners, while `cmd/debug/annotate` passes `""`. First error wins; subsequent stages do not run.
- `internal/unified/walker/` — Stage 1 of the unified-advisory pipeline. `Index(ctx, sourcesRoot) (map[string][]unified.IndexEntry, error)` walks `<sourcesRoot>/osv/<eco>/*.json` (light-unmarshals `id`+`aliases` only) and `<sourcesRoot>/cve/cvelistV5-main/cves/<year>/<bucket>/CVE-*.json` (filename-only). PrimaryID resolution per design §3.1: OSV with N CVE-ID aliases is duplicated under each, OSV without CVE alias is standalone. `IndexEntry.Source` is the OSV ecosystem dir name with spaces replaced by `_` (`Red Hat` → `Red_Hat`); the on-disk dir name is untouched, but every downstream consumer (writer's output path, unifier's priority tag) reads `Source` verbatim — no further normalization. Sequential walk (concurrency decided in #25). Any unreadable / malformed file aborts the entire walk — the index is intermediate state. Uses `os.OpenRoot` for symlink-safe reads.
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
- Caller: invoke via the `Agent` tool with `subagent_type: "codex:codex-rescue"`. Do NOT call the `codex:review` skill directly — it is user-invocation only (`disable-model-invocation`) and will fail when the model tries to launch it.
- Disposition: relay every Codex finding to the user, preserving each finding's severity (High/Medium/Low), affected files/lines, and Codex's overall verdict verbatim. Claude may add its own recommendation per finding but must not drop, re-rank, or downgrade items based on its own judgment. Do not auto-apply fixes — the user decides whether to address each point in a follow-up commit.
