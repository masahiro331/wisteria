# Ollama setup

Reference for installing and running [Ollama](https://ollama.com), a local HTTP server that wraps llama.cpp for LLM inference. Ollama exposes `POST /api/chat` (and other endpoints) on `127.0.0.1:11434` by default.

This document covers Ollama only. For how Wisteria invokes it, see the project [`README.md`](../../README.md).

---

## 1. Prerequisites

| | |
|---|---|
| OS | macOS 13+, Linux |
| Port | `11434/tcp` available on the host |
| Disk | Model weights are stored under the Ollama data directory (`~/.ollama` by default). `qwen3:8b` is ~5.2 GB. |

---

## 2. Setup A — macOS native

```bash
brew install ollama

# Background service, restarts at login:
brew services start ollama

# Or run in the foreground:
ollama serve

# Pull a model. Required once per model.
ollama pull qwen3:8b
```

Verify the server is running and the model is loaded:

```bash
curl -sS http://localhost:11434/api/tags | jq '.models[].name'
```

Reference: <https://ollama.com/download>

### GPU on macOS

Native Ollama uses Metal directly on Apple Silicon. Docker Desktop on macOS does not pass the Apple GPU through to Linux containers ([Docker docs](https://docs.docker.com/desktop/features/gpu/)), so Ollama inside a container on macOS runs on CPU.

---

## 3. Setup B — Linux + Docker Compose

The repo ships [`compose.yaml`](../../compose.yaml).

```bash
# Start the server. Default model directory: $HOME/.ollama on the host.
docker compose up -d

# Override the host directory:
WISTERIA_OLLAMA_DIR=/srv/ollama-models docker compose up -d
```

The host directory is bind-mounted into the container, so models persist across `docker compose down` and image upgrades, and a host that already has a native Ollama install reuses the same weights.

Pull a model into the container:

```bash
docker compose exec ollama ollama pull qwen3:8b
```

Verify:

```bash
curl -sS http://localhost:11434/api/tags | jq '.models[].name'
```

Stop:

```bash
docker compose down              # stop the container
rm -rf ${WISTERIA_OLLAMA_DIR:-~/.ollama}   # to also delete model files
```

`docker compose down --volumes` does not delete the bind-mounted host directory because it is not a Docker named volume.

### GPU on Linux + NVIDIA

Uncomment the `deploy.resources` block in `compose.yaml` and install the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html). Then `docker compose up -d` again.

References:
- Ollama Docker image: <https://hub.docker.com/r/ollama/ollama>
- Ollama Docker docs: <https://github.com/ollama/ollama/blob/main/docs/docker.md>

---

## 4. `qwen3:8b` model

| | |
|---|---|
| Architecture | Qwen3 |
| Parameters | 8.2 B |
| Quantization | Q4_K_M (default) |
| Disk size | ~5.2 GB |
| Context window | 40,960 tokens |
| Type | Thinking model |

`qwen3` is a thinking model: by default it emits a `<think>...</think>` block before the visible answer. The Ollama Chat API exposes a `think` boolean in the request body to suppress this. With `think: false`, the `<think>` block is not generated and `message.content` contains only the answer.

References:
- Qwen3 model card on Ollama: <https://www.ollama.com/library/qwen3>
- Qwen3 official model page: <https://huggingface.co/Qwen/Qwen3-8B>

---

## 5. Tuning fields on `/api/chat`

Sampling and runtime knobs the Ollama Chat API accepts, in addition to `model`, `messages`, `stream`, `format`, and `think`. Pass them in the `options` object of the request body. Defaults below are Ollama defaults; all values are model-tunable.

| Field | Type | Notes |
|---|---|---|
| `temperature` | number | Sampling temperature. `0` makes generation deterministic for the same prompt + model + parameters. |
| `num_ctx` | int | Context window size in tokens. Bounded above by the model's max (40,960 for `qwen3:8b`). Larger values increase KV cache memory. |
| `num_predict` | int | Maximum tokens to generate. `-1` means "until the model emits stop". For thinking models with `think:true`, this budget is shared between `<think>` and the visible answer. |
| `top_p` | number | Nucleus sampling threshold. |
| `top_k` | int | Top-k sampling. |
| `repeat_penalty` | number | Penalty applied to repeated tokens. |
| `seed` | int | RNG seed. With `temperature: 0` and a fixed seed, output is reproducible. |
| `stop` | []string | Strings that stop generation when emitted. |

Reference: <https://github.com/ollama/ollama/blob/main/docs/modelfile.md#parameter>

---

## 6. Switching models

```bash
ollama pull qwen3:4b          # smaller variant of the same family
ollama pull qwen2.5-coder:7b  # different family
ollama list                   # see what is installed locally
ollama rm <model>             # delete a model
```

Reference: <https://github.com/ollama/ollama/blob/main/README.md#quickstart>

---

## 7. References

- Ollama: <https://ollama.com>
- Chat API: <https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-chat-completion>
- Structured outputs: <https://docs.ollama.com/capabilities/structured-outputs>
- Modelfile parameters: <https://github.com/ollama/ollama/blob/main/docs/modelfile.md#parameter>
