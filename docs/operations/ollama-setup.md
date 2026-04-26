# Ollama setup for Wisteria Phase 2

Wisteria's Phase 2 AI layer (`internal/ai/ollama` + `wisteria debug ai summarize`) talks to a local Ollama server over `POST /api/chat`. This document covers the two supported ways to run that server, the model Wisteria currently uses (`qwen3:8b`), and the runtime knobs worth touching.

Design references: [`docs/design/ai-advisory-summary.md`](../design/ai-advisory-summary.md), Issue #57 (debug command), Issue #31 (Ollama client).

---

## 1. Overview

| | |
|---|---|
| Server | [Ollama](https://ollama.com) — local HTTP wrapper around llama.cpp / metal / CUDA |
| Endpoint | `http://localhost:11434` (Wisteria default) |
| Model | `qwen3:8b` (Q4_K_M, ~5.2 GB on disk, 40K context) |
| Wire format | `/api/chat`, `stream:false`, `format` = JSON Schema for `AdvisoryAISummary` |
| Wisteria default | `Client.Think = false` to suppress qwen3 chain-of-thought |

The Wisteria binary does not ship Ollama. You install it once on the host (or run it in Docker) and `wisteria debug ai summarize` reaches it over HTTP.

---

## 2. Prerequisites

| | |
|---|---|
| OS | macOS 13+ (Apple Silicon) or Linux |
| RAM | 16 GB recommended for `qwen3:8b`. 8 GB → use `qwen3:4b` (see §6) |
| Disk | ~6 GB free for the qwen3:8b weights |
| Port | `11434/tcp` available on the host |

---

## 3. Setup A — macOS native (recommended for Apple Silicon)

Docker Desktop on macOS cannot expose the Apple GPU to a Linux container. Native Ollama uses Metal directly, which is several times faster than CPU inference inside Docker. On M1 16 GB, native `qwen3:8b` answers a single advisory in ~30 seconds; the same call inside Docker on the same host falls to CPU and takes minutes.

```bash
brew install ollama

# Background service (auto-restart at login):
brew services start ollama

# OR run in the foreground for one session:
ollama serve

# Pull the model Wisteria uses by default. ~5.2 GB download.
ollama pull qwen3:8b
```

Verify:

```bash
curl -sS http://localhost:11434/api/tags | jq '.models[].name'
# "qwen3:8b"
```

---

## 4. Setup B — Linux + Docker Compose

Use this when the host has an NVIDIA GPU, or when you want a disposable server that does not pollute the host. The repo ships [`compose.yaml`](../../compose.yaml).

### 4.1 Bring up the server

```bash
# Default model directory: ${HOME}/.ollama on the host.
docker compose up -d

# Override the host directory (useful on shared boxes):
WISTERIA_OLLAMA_DIR=/srv/ollama-models docker compose up -d
```

The bind mount means models persist across `docker compose down` / image upgrades; pulling a model only happens once. If you already had `~/.ollama` populated by a native install, the container picks up those weights automatically.

### 4.2 Enable the GPU (Linux + NVIDIA only)

Uncomment the `deploy.resources` block in `compose.yaml` and install the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html). Then `docker compose up -d` again.

Apple Silicon: leave the block commented. Docker on macOS will not pass Metal through.

### 4.3 Pull the model

```bash
docker compose exec ollama ollama pull qwen3:8b
```

### 4.4 Verify

```bash
curl -sS http://localhost:11434/api/tags | jq '.models[].name'
```

### 4.5 Stop / remove

```bash
docker compose down              # stop the container, keep models
docker compose down --volumes    # ALSO unmount; the bind mount is not deleted
```

The bind mount is a host directory, not a Docker named volume — `--volumes` does not delete the model files. To reclaim disk, delete the host directory (`rm -rf ${WISTERIA_OLLAMA_DIR:-~/.ollama}`).

---

## 5. Calling Ollama from Wisteria

After §3 or §4 the rest of the workflow is the same.

### Build

```bash
make build
```

### One advisory from stdin

```bash
echo '{
  "primary_id": "CVE-2024-3094",
  "descriptions": [{
    "lang": "en",
    "text": "Malicious code in xz 5.6.0 backdoor in liblzma.",
    "from": {"kind": "osv", "path": "", "id": "GHSA-rxwq-x6h5-x525"}
  }]
}' | ./wisteria debug ai summarize --from-stdin
```

### One advisory by PrimaryID, from the cache

```bash
./wisteria debug ai summarize --id CVE-2024-0001 --cache-dir ~/.cache/wisteria
```

### Useful flags

| Flag | Default | Notes |
|---|---|---|
| `--from-stdin` | off | Read one `UnifiedAdvisory` JSON from stdin |
| `--id <CVE-ID>` | — | Read by PrimaryID from `<cache-dir>/unified/cve/<year>/` |
| `--provider` | `ollama` | Only `ollama` is implemented today; Anthropic / Bedrock land later |
| `--model` | `qwen3:8b` | Pass through to the provider |
| `--endpoint` | `http://localhost:11434` | Useful when the server runs on another host / port |
| `--think` | off | Re-enable provider-side chain-of-thought (see §6) |
| `--cache-dir` | `$WISTERIA_CACHE_DIR` or user cache dir | Where `unified/` lives |

---

## 6. Tuning guide

### 6.1 Model choice

| Model | Size | When to pick it |
|---|---|---|
| `qwen3:8b` | 5.2 GB | Default. M1 16 GB / Linux 16 GB+. Best summary quality of the qwen3 line tested so far. |
| `qwen3:4b` | ~2.5 GB | 8 GB RAM, batch runs where many parallel requests would push 16 GB into swap, or as a fallback when 8b is too slow. |
| `qwen2.5-coder:7b` | ~4.4 GB | Candidate when Stage 2 starts analyzing patches / diffs (currently out of scope; not used by Wisteria today). |

To switch:

```bash
ollama pull qwen3:4b
./wisteria debug ai summarize --from-stdin --model qwen3:4b < advisory.json
```

The default in code is `qwen3:8b`; `--model` overrides for one invocation.

### 6.2 Think (chain-of-thought)

`Client.Think` (CLI: `--think`) controls Ollama's `think` field. **Wisteria defaults it to `false`.** Reason:

- qwen3 is a thinking model. With `think:true` (Ollama default), the model spends `num_predict` tokens inside a hidden `<think>...</think>` block and frequently returns an empty `message.content`. Observed live: a single Summarize call took 2 m 3 s and returned `""`.
- With `think:false` the same prompt returns a structured `AdvisoryAISummary` in ~30 s.

Re-enable `--think` only if you swap to a non-thinking model that benefits from chain-of-thought, or if you are benchmarking a future reasoning model on the exact same prompt.

### 6.3 Sampling parameters

These are baked into `internal/ai/ollama` per design §12 and are **not currently exposed as CLI flags**:

| Parameter | Default | Why this value |
|---|---|---|
| `temperature` | `0` | The output is constrained by a JSON Schema; we want deterministic schema-conforming text, not creative phrasing |
| `num_ctx` | `8192` | Comfortable headroom for `UnifiedAdvisory` JSON + prompts; below the qwen3:8b limit (40 K) but cheap on the KV cache |
| `num_predict` | `1200` | Plenty for the 11-field `AdvisoryAISummary` envelope; raise only if you re-enable `--think` and the model needs room for both |

If you need to retune for a different model, edit `internal/ai/ollama/client.go` (constants near the top) — adding flags is a follow-up that should land alongside batch-mode CLI work.

### 6.4 Memory pressure

`qwen3:8b` resident size on M1 16 GB is roughly:

- Model weights: ~4.5 GB on the GPU
- KV cache (`num_ctx=8192`): ~1.1 GB
- Compute graph: ~120 MB

That leaves enough free memory for Chrome and an editor, but **a second concurrent request** doubles the KV cache and starts to thrash. For now keep concurrency = 1 (the design §9 batch CLI is not implemented yet). When it lands, it should default to 1 on Mac and let CI / Linux GPU hosts opt up.

### 6.5 Switching the endpoint

If Ollama runs on another machine (lab GPU box, shared dev server):

```bash
./wisteria debug ai summarize --from-stdin \
  --endpoint http://gpu-box.example.internal:11434 < advisory.json
```

The client does not currently authenticate to the endpoint — point it at trusted hosts only.

---

## 7. References

- Ollama Chat API: <https://docs.ollama.com/api/chat>
- Ollama Structured Outputs: <https://docs.ollama.com/capabilities/structured-outputs>
- Qwen3 model card: <https://www.ollama.com/library/qwen3>
- Wisteria design: [`docs/design/ai-advisory-summary.md`](../design/ai-advisory-summary.md)
- Wisteria client code: `internal/ai/ollama/client.go`, `internal/ai/summary.go`
- Wisteria debug command: `cmd/debug/ai.go`
