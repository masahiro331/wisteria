# §8 Merge rule validation pass — 2026-04-29

Issue #23 acceptance: "if surprises appear, the rules in design §8 are updated; if not, leave a note recording the validation pass."

## Method

Ran `wisteria debug unify --sample N` (introduced in this same PR) and `wisteria debug unify --id <ID>` against the local `tmp/sources` tree. The `--sample N` mode picks the lex-sorted first N PrimaryIDs and emits NDJSON, which is reproducible across runs.

`tmp/sources` snapshot used:

- OSV: 30+ ecosystems including `AlmaLinux`, `[EMPTY]` (renamed locally to `Generic` by this PR — see "Surprise found" below), `Go`, `PyPI`, `npm`, `GitHub Reviewed`, `Red Hat`, `Ubuntu`, ...
- CVE5: full `cvelistV5-main` tree with ADP containers (CISA Vulnrichment etc.) on many records.

Targeted observations were taken on a handful of well-known CVE-IDs that span multiple sources:

- `CVE-2024-3094` (xz-utils backdoor; OSV GIT + CVE5 CNA + ADP)
- `CVE-2021-44228` (log4shell; OSV GHSA + CVE5 CNA + ADP)
- `CVE-2014-0160` (heartbleed; OSV `[EMPTY]` (now `Generic`) + CVE5 CNA + 2 ADPs)
- `CVE-2024-0001` (small fixture; CVE5 CNA + CISA ADP)

## Findings against §8

### §8.2 References — URL normalization, dedup, tag union

- Lowercase scheme/host: confirmed. No mixed-case URLs in any sample output.
- Trailing-slash strip: confirmed (no `*/` URLs in 75-ref log4shell or 129-ref heartbleed outputs).
- Fragment strip: confirmed.
- Dedup by normalized URL with tag union: confirmed (log4shell tags include OSV-side `WEB`, `ADVISORY`, `PACKAGE` + CVE5 `vdb-entry`, `x_refsource_REDHAT`, `x_transferred` — no per-URL duplicates).
- Sort order: lex by normalized URL. Confirmed.

No §8.2 surprises. Rule unchanged.

### §8.3 Descriptions — parallel hold

- CNA + ADP + OSV all retained as separate entries even when text is identical (xz-utils CVE has byte-identical CNA and OSV descriptions; both kept). Documented as design intent so the AI summarizer can pick.
- Sort: priority rank → lang → input index. CNA (rank 0, no `#adp`) comes before ADP (rank 0, but later ID lex), comes before OSV ecosystems. Confirmed.

No §8.3 surprises. Rule unchanged.

### §8.4 Severities — (Type, Vector) / (Type, Score) dedup

- Cross-source same-vector dedup: xz-utils has matching `CVSS:3.1/AV:N/...` from OSV and CVE5; output is one entry with CVE provenance (CVE outranks OSV). Confirmed.
- Same-Type-different-Vector kept as separate entries: CVE-2024-0001 emits both `S:C` and `S:U` variants (CNA scope-changed vs ADP scope-unchanged). Confirmed.
- Sort tie-breaker (Type → Vector → Score): not directly observable in the small sample but the pure-function tests in `internal/unified/unifier/severities_test.go` cover this.

No §8.4 surprises. Rule unchanged.

### §8.5 Affected — parallel hold + ADP suffix

- Parallel hold: log4shell emits 12 affected entries spanning CNA + ADP + OSV without merging. Confirmed.
- ADP suffix `#adp:<shortName>`: heartbleed emits both `CVE-2014-0160#adp:CVE` and `CVE-2014-0160#adp:CISA-ADP`. The first one is unintuitive but follows the upstream `providerMetadata.shortName` verbatim — that ADP container literally identifies its provider as `"CVE"`. xz CVE-2024-0001 emits `#adp:CISA-ADP`. Both the suffix and the multiple-ADP-per-record case are working as designed.

No §8.5 surprises. Rule unchanged.

### §8.6 KEV / EPSS

Out of scope for `debug unify`; covered by Stage 4 annotator and tested separately.

## Surprise found and fixed: `[EMPTY]` ecosystem leaks through Provenance.Path

Heartbleed CVE-2014-0160 originally produced:

```json
"provenances": [{
  "kind": "osv",
  "path": "osv/[EMPTY]/CVE-2014-0160.json",
  "id": "CVE-2014-0160"
}, ...]
```

`[EMPTY]` is the literal ecosystem name OSV upstream uses for ecosystem-less generic advisories — it appears in `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` as a real entry. The fetcher / walker / unifier had been passing it through verbatim, leaving the brackets in `Provenance.Path`, `IndexEntry.Source`, the standalone bucket directory, and any future API surface.

Square brackets are filesystem-legal but they need escaping in shell globs (`unified/standalone/\[EMPTY\]/...`), and "ecosystem named `[EMPTY]`" is a confusing label for downstream consumers (priority array, AI summarizer prompts).

**Fix in this PR**: the OSV fetcher renames `[EMPTY]` to `Generic` at download time (`internal/fetcher/osv/osv.go:localEcosystem`). The upstream URL path keeps `[EMPTY]/all.zip` because the OSV bucket lookup requires the literal sentinel; only the local on-disk directory is renamed. Downstream stages (walker / unifier / writer) see `Generic` verbatim and need no special-case handling.

Operators with an existing `tmp/sources/osv/[EMPTY]/` directory should re-run `wisteria fetch osv` to switch to the renamed layout. The old directory can be deleted manually (this PR does not auto-migrate it — the fetcher only knows how to download, not how to reconcile pre-existing layout drift).

The §8.1 vendor priority array still does not list `osv.Generic` explicitly; it ranks last via `defaultRank`, which is consistent with treating it as a low-information generic source. Whether `osv.Generic` should be added to the array is part of the open question in #22 and intentionally not decided here.

## Conclusion

§8.1 / §8.2 / §8.3 / §8.4 / §8.5 all behave as documented on the sampled real records. No rule changes.

One surprise found (`[EMPTY]` literal leaking through Provenance) and fixed in the same PR.
