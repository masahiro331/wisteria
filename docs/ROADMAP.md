# Roadmap

Tracks planned work across phases. See `docs/SYSTEM_OVERVIEW.md` for the current product shape.

Each item is either **decided** (scope/intent agreed) or **to decide** (needs a design call). Anything labeled "to decide" is itself a task — make the decision, then move it under "Decided" before implementing.

## Phase 1 — Source ingestion (current)

### To decide

- **Periodic / scheduled fetch** — decide whether wisteria runs as a one-shot CLI under cron / systemd timer, exposes its own scheduler, or both. Affects locking, concurrent-run protection, and where state (last-success timestamp) lives.
- **Source coverage beyond the current five** — e.g. NVD, GHSA, distro advisories. Not part of MVP, but record candidates here as they come up.
- **Vendor priority array final members (§8.1)** — pin the membership of `unifier.sourcePriority` once enough real-data observations are in.
- **Signal-only UnifiedAdvisory** — decide whether to synthesize a UnifiedAdvisory for KEV / EPSS / Exploit-DB CVE-IDs that have no advisory in OSV / CVE5. Today the annotator silently skips them.

## Phase 2 — AI processing (in progress)

### Decided / planned

- Use a local LLM (Ollama, currently `qwen3:8b`) and the Claude API for AI-driven fields: product overview summary, vulnerability summary, exploit analysis, labeling.
- A `Summarizer` interface (`internal/ai`) is the seam between providers; today only the Ollama implementation is wired.
- AI output is deterministic-side-quarantined: keep AI artifacts under a separate `ai-summary/` tree (or a `UnifiedAdvisory.AI` field — to be decided) so unified records stay reproducible.

### To decide

- **Model split** — which fields go to Claude API vs the local LLM. Driven by cost, latency, and reproducibility per field.
- **Prompt + caching strategy** — how to apply Anthropic prompt caching across many CVEs (system prompt + per-record context).
- **AI output validation** — JSON schema enforcement, retry policy on malformed output, and how to record prompt + model version next to each AI-generated field for reproducibility.
- **Output layout** — `<cache-dir>/ai-summary/...` separate tree vs embedded in `UnifiedAdvisory`.
- **Exploit-code judgment (req 5b)** — how to combine the deterministic Exploit-DB / KEV signal with AI-judged exploitability.
- **In-the-wild signal (req 8)** — define inputs (KEV, social media, news?) and how the score is computed.

## Phase 3 — Storage (not yet started)

### Decided / planned

- Backing store is PostgreSQL.
- Each record carries a stable product identifier so naming variations across sources collapse deterministically.

### To decide

- **Product identifier scheme** — CPE? PURL? custom? Markov-chain assisted clustering with AI fallback? Decide after Phase 1 has produced enough samples to inspect the naming variation space.
- **Schema shape** — table layout for vulnerabilities, products, references, AI-generated fields, scores. Includes how AI-generated fields are versioned (model id, prompt id, generated-at).
- **Migration tooling** — pick a migration runner (sqlc + golang-migrate? atlas? plain SQL?) before the first table lands.
- **Ingestion pipeline** — how Phase 1's on-disk JSON gets into Postgres (one-shot loader vs streaming, idempotency, change detection).
