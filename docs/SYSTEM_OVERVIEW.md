# System Overview

## Product

**Wisteria** is a free, fast vulnerability database builder. It is a Go CLI that:

1. Aggregates vulnerability data from public sources (OSV, MITRE CVEListV5, CISA KEV, FIRST EPSS, Exploit-DB).
2. Merges per-source advisories into a single `UnifiedAdvisory` record per PrimaryID, then annotates each record with KEV / EPSS / Exploit-DB signals.
3. (Future) Enriches each record with AI-generated summaries, labels, and exploit analysis using a local LLM (Ollama) and the Claude API.
4. (Future) Stores the unified, enriched data in PostgreSQL with a stable product identifier scheme.

The goal is a vulnerability database that does not depend on a commercial vendor.

## Phases

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Source ingestion + unify pipeline (Stage 1-4) | In progress |
| 2 | AI processing (Ollama local LLM + Claude API) — summaries, labels, exploit analysis | Local LLM scaffolding lives under `internal/ai/ollama` and `cmd/debug/ai.go`; production wiring not started |
| 3 | PostgreSQL storage and product identifier design | Not started |

See `docs/ROADMAP.md` for the per-phase task list.

## CLI

Production:

```
wisteria fetch osv | cve | kev | epss | exploitdb | all
wisteria unify --cache-dir <path> [--concurrency N] [--cpuprofile <file>]
```

Debug (developer-only, ships in the same binary):

```
wisteria debug index [--id <PrimaryID>]
wisteria debug unify --id <PrimaryID> | --sample N
wisteria debug annotate
wisteria debug ai summarize --id <CVE-ID> | --from-stdin
```

The `debug ai summarize` command currently only resolves CVE-ID lookups; standalone PrimaryID support is a follow-up. It also accepts provider knobs (`--provider`, `--model`, `--endpoint`, `--think`) for swapping the underlying summarizer.

Common flags (see `wisteria <cmd> --help` for the full list):
- `--cache-dir` — override the on-disk root.
- `--concurrency` — cap parallel work (fetcher downloads or unify fan-out).
- `--retries` — HTTP retry attempts (default 3).

## On-disk layout

Default root: `os.UserCacheDir()/wisteria` (override via `--cache-dir` or `WISTERIA_CACHE_DIR`).

```
<cache-dir>/
├── sources/                                 ← raw download targets (fetcher output)
│   ├── osv/<ecosystem>/*.json
│   ├── cve/cvelistV5-main/cves/<year>/<bucket>/CVE-*.json
│   ├── kev/known_exploited_vulnerabilities.json
│   ├── epss/epss_scores-current.csv         ← gzip-decompressed at download time
│   └── exploitdb/files_exploits.csv
└── unified/                                 ← merge output (unify command)
    ├── cve/<year>/<CVE-ID>.json             ← PrimaryID is a CVE-ID
    └── standalone/<ecosystem>/<id>.json     ← PrimaryID is a source-derived ID
```

Archives (`.zip`, `.tar.gz`, `.gz`) are removed after extraction.

## Architecture

- `main.go` — entrypoint; wires a signal-aware context into Cobra.
- `cmd/` — CLI surface.
  - `cmd/unify.go` is a thin wrapper around `internal/unified/pipeline.Run`.
  - `cmd/debug/` hosts the inspection subcommands (`debug index | unify | annotate | ai`).
- `internal/fetcher/` — source integrations behind a shared `Fetcher` interface (`Name()`, `Fetch(ctx) (dir, error)`).
  - `osv/`, `cve/`, `kev/`, `epss/`, `exploitdb/` — per-source fetchers.
  - `progress/` — fetcher-side progress UI (`mpb` wrapper).
- `internal/unified/` — Stage 1-4 of the unified-advisory pipeline.
  - `walker/` (Stage 1) — index sources by PrimaryID.
  - `unifier/` (Stage 2) — `MergePrimary(ctx, sourcesRoot, primaryID, entries)` produces one `UnifiedAdvisory` per PrimaryID. Field-level merge functions (`mergeReferences` / `mergeDescriptions` / `mergeSeverities` / `mergeAffected`) share a generic `stableSortByPriority` helper.
  - `writer/` (Stage 3) — atomic per-record writes into the bucketed output tree.
  - `annotator/` (Stage 4) — `RunAll` runs KEV → EPSS → ExploitDB in order against the existing `unified/` tree.
  - `pipeline/` — orchestrates Stage 1-4 with a bounded errgroup fan-out.
  - `osv/`, `cve/`, `kev/`, `epss/`, `exploitdb/` — typed schema types (1 byte not lost rule, see `docs/design/unified-advisory.md` §7).
- `internal/ai/` — Phase 2 scaffolding.
  - `ai.go` defines the `Summarizer` interface.
  - `ollama/` is the local-LLM client (chat API + structured output).
- `internal/x/` — cross-cutting utilities.
  - `archive/` — `Zip` / `TarGz` extractors; both reject zip-slip / tar-slip entries.
  - `cachedir/` — resolves and creates per-source on-disk directories.
  - `http/` (package `xhttp`) — `DoWithRetry` with exponential backoff + jitter; retries 5xx and transport errors.

### Testing seams

Fetchers expose `WithBaseURL` / `WithArchiveURL` / `WithCatalogURL` and `WithHTTPClient` options so tests can inject `httptest.Server`. Tests override `HOME` and `XDG_CACHE_HOME` to redirect cache writes into `t.TempDir()`.

## Vulnerability DB requirements (target shape)

Each record will eventually carry:

0. A unique identifier for the affected product (deterministic name resolution, AI-assisted where needed).
1. Product overview summary (AI, multi-source).
2. Vulnerability identifier (deterministic).
3. Vulnerability summary (AI, multi-source) including chainable exploit types.
4. Vulnerability references (deterministic).
5. Exploit-code existence (deterministic from Exploit-DB / KEV) plus AI judgment on exploitability or the cost of developing an exploit.
6. EPSS / CVSS / attack vector (deterministic).
7. Vulnerability labeling such as XSS or prototype pollution (AI).
8. In-the-wild signal — "social temperature".

Phase 1 covers items 2, 4, 5 (deterministic side), 6. Items 0, 1, 3, 5 (AI side), 7, 8 land in Phases 2-3.
