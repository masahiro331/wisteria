# Wisteria

Wisteria is a free, fast vulnerability database builder.

It is a Go CLI that aggregates vulnerability data from public sources (OSV, MITRE CVEListV5), and — across later phases — enriches it with AI-generated summaries and stores everything in PostgreSQL.

See [`docs/SYSTEM_OVERVIEW.md`](docs/SYSTEM_OVERVIEW.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md) for more details.

## Quick Start

### Prerequisites

- Go 1.25+
- A running [Ollama](https://ollama.com) server with `qwen3:8b` pulled — see [`docs/operations/ollama-setup.md`](docs/operations/ollama-setup.md).

### 1. Build

```bash
make build
```

### 2. Fetch upstream sources

Downloads OSV / MITRE CVEListV5 / CISA KEV / FIRST EPSS into `<cache-dir>/sources/`.

```bash
./wisteria fetch all --cache-dir ./.cache/wisteria
```

Per-source subcommands also exist: `fetch osv`, `fetch cve`, `fetch kev`, `fetch epss`. The default cache directory follows `$WISTERIA_CACHE_DIR` then `os.UserCacheDir()/wisteria`.

### 3. Build the unified advisory tree

Runs the Stage 1–4 pipeline (walker → unifier → writer → annotator) and writes per-record JSON under `<cache-dir>/unified/`.

```bash
./wisteria unify --cache-dir ./.cache/wisteria
```

### 4. Summarize one advisory with the local LLM (debug)

```bash
./wisteria debug ai summarize \
  --id CVE-2024-3094 \
  --cache-dir ./.cache/wisteria
```

The `debug ai summarize` command also accepts `--from-stdin` to take a `UnifiedAdvisory` JSON document directly:

```bash
cat advisory.json | ./wisteria debug ai summarize --from-stdin
```

Provider / model / endpoint are configurable:

```bash
./wisteria debug ai summarize \
  --from-stdin \
  --provider ollama \
  --model qwen3:8b \
  --endpoint http://localhost:11434 \
  < advisory.json
```

`wisteria debug --help` lists the other inspection helpers (`debug index`, `debug unify`, `debug annotate`).
