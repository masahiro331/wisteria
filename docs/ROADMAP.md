# Roadmap

Tracks feature requests, in-progress work, and ideas across phases.
See `docs/SYSTEM_OVERVIEW.md` for the current product shape and
`docs/meetings/2026-04-25-project-design.md` for the original requirements.

Each item is either **decided** (scope/intent agreed) or **to decide**
(needs a design call). Anything labeled "to decide" is itself a task — make
the decision, then move it under "Decided" before implementing.

## Phase 1 — Source ingestion (current)

### Done
- OSV per-ecosystem fetcher with parallel downloads, retries, progress bars, and zip extraction
- MITRE CVEListV5 fetcher with retries and tar.gz extraction
- `internal/x/{archive,cachedir,http}` shared utilities; `internal/fetcher/progress` for fetcher progress UI
- CI: lint (`golangci-lint`) and test workflows on push/PR

### Decided / planned
- **Streaming extraction for CVE (tar.gz)** — pipe `resp.Body → gzip → tar` to drop the on-disk tarball and overlap network with extraction. tar is sequential so this is straightforward.
- **OSV zip handling stays as-is** — zip needs `io.ReaderAt`+size (central directory at EOF), so true streaming is not possible. If the temp file ever becomes a footprint problem, switch to `os.CreateTemp` for guaranteed cleanup; no perf win expected.

### To decide
- **Periodic / scheduled fetch** — the design meeting calls for "periodic batch execution". Decide whether wisteria runs as a one-shot CLI under cron/systemd timer, exposes its own scheduler, or both. Affects locking, concurrent-run protection, and where state (last-success timestamp) lives.
- **Pipeline OSV download + extract** — currently both happen in the same goroutine per ecosystem. Whether to split into a download pool feeding an extraction pool depends on profiling (network-bound vs disk-bound). To decide once we have real numbers.
- **Source coverage beyond OSV/CVE** — e.g. NVD, GHSA, distro advisories. Not part of MVP, but record candidates here as they come up.

## Phase 2 — AI processing (not yet started)

### Decided / planned
- Use Claude API + a local LLM (OSS) for the AI-driven fields: product overview summary, vulnerability summary, exploit analysis, labeling.
- Vulnerability fields owned by AI per the design meeting: 1, 3, 5a/5b, 7 (see SYSTEM_OVERVIEW).

### To decide
- **Model split** — which fields go to Claude API vs the local LLM. Likely driven by cost, latency, and reproducibility requirements per field.
- **Prompt + caching strategy** — how to apply Anthropic prompt caching across many CVEs (system prompt + per-record context).
- **AI output validation** — schema/JSON-mode use, retry policy on malformed output, and whether/how to record the prompt+model version next to each AI-generated field for reproducibility.
- **Exploit-code existence (req 5)** — the deterministic side (reference scrape from public PoC sources) needs a source list before the AI judgment layer can sit on top.
- **In-the-wild signal (req 8, "social temperature")** — define inputs (CISA KEV, social media, news?) and how the score is computed.

## Phase 3 — Storage (not yet started)

### Decided / planned
- Backing store is PostgreSQL.
- Each record carries a stable product identifier so naming variations across sources collapse deterministically.

### To decide
- **Product identifier scheme** — explicitly deferred in the design meeting until real OSV/CVE data is in hand. Decide after Phase 1 has produced enough samples to inspect the naming variation space (CPE? PURL? custom? Markov-chain assisted clustering with AI fallback?).
- **Schema shape** — table layout for vulnerabilities, products, references, AI-generated fields, scores. Includes how AI-generated fields are versioned (model id, prompt id, generated-at).
- **Migration tooling** — pick a migration runner (sqlc + golang-migrate? atlas? plain SQL?) before the first table lands.
- **Ingestion pipeline** — how Phase 1's on-disk JSON gets into Postgres (one-shot loader vs streaming, idempotency, change detection).
