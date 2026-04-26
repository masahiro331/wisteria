# 設計: AI Advisory Summary

UnifiedAdvisory を入力に、ローカル LLM で脆弱性 advisory の英語サマリーと構造化フィールドを生成する Phase 2 の設計。

関連: `docs/design/unified-advisory.md`、`docs/SYSTEM_OVERVIEW.md`、`docs/ROADMAP.md`

## 1. ゴール

- `unified/` 配下の UnifiedAdvisory JSON を読み、AI 処理用の入力 prompt を作る。
- ローカル LLM で advisory summary を英語で生成する。
- JSON Schema に従う structured output として結果を受け取る。
- 生成結果を Go の struct に unmarshal し、後続の DB 投入や検索 UI で扱える形にする。
- M1 Mac 2020 / 16GB で安定稼働する構成を前提にする。

## 2. 非ゴール

- RAG / vector search
- agent workflow
- tool calling
- cloud LLM 連携
- 画像入力
- 日本語サマリー生成
- AI 結果の PostgreSQL schema 確定

## 3. ランタイム / モデル選定

### 採用

- Runtime: Ollama
- Model: `qwen3:8b`
- Integration: Go から Ollama REST API (`POST /api/chat`) を直接呼ぶ
- Structured output: `/api/chat` の `format` に JSON Schema を渡す

### 理由

- `qwen3:8b` は Ollama 版で 5.2GB / 40K context window の text model。M1 16GB で advisory 要約用途に現実的。
- Ollama は JSON Schema を `format` に渡す structured outputs に対応している。
- Go では薄い REST client の方が依存が少なく、バッチ処理へ組み込みやすい。
- LangChainGo などの framework は chain / agent / RAG が必要になるまで導入しない。

### fallback

M1 16GB で `qwen3:8b` が重い場合は `qwen3:4b` に落とす。

- 高品質優先: `qwen3:8b`
- 安定 / 大量処理優先: `qwen3:4b`
- コード差分や patch 解析も強くしたい場合の候補: `qwen2.5-coder:7b`

## 4. ローカルセットアップ

```bash
brew install ollama
ollama serve
ollama pull qwen3:8b
```

動作確認:

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "qwen3:8b",
  "stream": false,
  "messages": [
    {"role": "user", "content": "Summarize CVE-2024-0001 in one sentence."}
  ]
}'
```

## 5. 出力 schema

初版では以下の構造を生成する。

```go
type AdvisoryAISummary struct {
    Title              string   `json:"title"`
    AffectedProducts   []string `json:"affected_products"`
    VulnerabilityType  *string  `json:"vulnerability_type"`
    Impact             *string  `json:"impact"`
    AffectedVersions   []string `json:"affected_versions"`
    FixedVersions      []string `json:"fixed_versions"`
    Severity           *string  `json:"severity"`
    ExploitationStatus *string  `json:"exploitation_status"`
    RecommendedAction  *string  `json:"recommended_action"`
    Confidence         float64  `json:"confidence"`
    MissingInformation []string `json:"missing_information"`
}
```

ルール:

- 不明な string field は `null`。
- 不明な array field は `[]`。
- `confidence` は `0.0` から `1.0`。
- 入力 advisory に存在しない事実は作らない。
- exploit / KEV / EPSS の判断は UnifiedAdvisory に含まれる情報だけを根拠にする。

## 6. Prompt 方針

System prompt:

```text
You summarize vulnerability advisories for security engineers.
Return only JSON that matches the provided schema.
Do not invent facts.
Use null or [] when the input does not contain enough information.
Prefer concrete affected products, versions, fixed versions, impact, and recommended action.
```

User prompt:

```text
Summarize this vulnerability advisory in English.

PrimaryID: <CVE-ID or other primary identifier>

Input UnifiedAdvisory JSON:
<json>
```

`PrimaryID:` 行は雛形に対する小さな追加。JSON 内にも `primary_id` は入っているが、model が要約タスクでまず参照する識別子を冒頭に置いた方が `title` の一貫性が上がる。

JSON Schema は Ollama request の `format` に渡す。schema 自体も prompt に含めると model が安定しやすいが、初版では `format` を主たる制約として使う。

## 7. Go I/F

`internal/ai/ollama` に小さな client を置く。

```go
package ollama

type Client struct {
    Endpoint string // default: http://localhost:11434
    Model    string // default: qwen3:8b
    HTTP     *http.Client
    Think    *bool  // default: false (suppress qwen3 chain-of-thought)
}

func (c *Client) Summarize(ctx context.Context, advisory unified.UnifiedAdvisory) (*AdvisoryAISummary, error)
```

実装方針:

- `POST /api/chat` を `stream: false` で呼ぶ。
- `think: false` を送る。qwen3 系は thinking model で、デフォルト動作だと `<think>...</think>` で `num_predict` を使い切り `message.content` が空のまま `done` になる。要約用途なので chain-of-thought は不要、`think:false` でレイテンシを 2 分超 → 数秒に下げる。`Client.Think` で opt-in に戻せる。
- `format` に JSON Schema を渡す。
- `options.temperature = 0`。
- `options.num_ctx = 8192` から開始する。
- `options.num_predict = 1200` から開始する。
- response の `message.content` を `encoding/json` で `AdvisoryAISummary` に unmarshal する。
- unmarshal 失敗時は raw content を含めて error にする。
- domain validation は Go 側で行う (`confidence` range、必須 array nil 回避など)。

## 8. JSON Schema 生成

初版は schema を手書きする。理由:

- 出力項目が少ない。
- Ollama の structured output に渡す schema を最小化しやすい。
- model が解釈しづらい `$defs` や複雑な draft feature を避けられる。

必要になったら `github.com/invopop/jsonschema` で Go struct から schema を生成する。ただし生成 schema は Ollama に渡す前に確認し、不要な `$schema` / `$id` / `$defs` が複雑になりすぎないようにする。

## 9. 実行設計

初版は逐次実行にする。

```text
Read unified JSON → Build prompt → Ollama chat → Validate JSON → Write AI result
```

並列化は後回し。M1 16GB では `qwen3:8b` の同時実行はメモリ圧迫につながるため、まず concurrency = 1 で計測する。

出力先は未決定。候補:

- UnifiedAdvisory に `ai_summary` field を追記する
- `<cache-dir>/ai-summary/...` に別ファイルとして保存する

初版では後者を優先する。AI 出力は model / prompt / schema version に依存するため、deterministic な unified output と分けた方が差分管理しやすい。

想定 layout:

```text
<cache-dir>/
├── unified/
└── ai-summary/
    ├── cve/<year>/<CVE-ID>.json
    └── standalone/<ecosystem>/<id>.json
```

## 10. CLI

候補:

```bash
wisteria ai summarize --cache-dir <path>
wisteria ai summarize --id CVE-2024-0001
wisteria ai summarize --limit 100
wisteria ai summarize --model qwen3:8b
```

初版では `--id` を先に実装し、1 advisory の prompt / output を確認できるようにする。その後 batch 処理を追加する。

## 11. テスト戦略

- schema validation:
  - sample JSON が `AdvisoryAISummary` に unmarshal できること
  - `confidence` が range 外なら validation error
- prompt builder:
  - UnifiedAdvisory の主要 field が prompt に含まれること
  - 入力 JSON が壊れないこと
- Ollama client:
  - `httptest.Server` で `/api/chat` request body を検証
  - `model`, `stream`, `format`, `options.temperature`, `messages` が期待通りであること
  - response の `message.content` を decode できること
- integration:
  - local Ollama がある環境だけで `qwen3:8b` smoke test を実行
  - 通常の `go test ./...` からは skip できるようにする

## 12. 運用パラメータ

M1 Mac 2020 / 16GB の初期値:

```json
{
  "temperature": 0,
  "num_ctx": 8192,
  "num_predict": 1200
}
```

運用メモ:

- 同時実行数は 1 から開始。
- 長すぎる advisory は入力を source ごとに絞るか、Description / Affected を優先度順に truncate する。
- `qwen3:8b` が重い場合は `qwen3:4b` に切り替える。
- model 名、prompt version、schema version は出力 JSON に保存する。

## 13. 参照

- Ollama Structured Outputs: https://docs.ollama.com/capabilities/structured-outputs
- Ollama Chat API: https://docs.ollama.com/api/chat
- Ollama Qwen3: https://www.ollama.com/library/qwen3
- Go JSON Schema generator: https://github.com/invopop/jsonschema
