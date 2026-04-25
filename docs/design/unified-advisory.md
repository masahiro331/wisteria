# 設計: Unified Advisory

Phase 1 で取得した OSV / MITRE CVEListV5 のローカル JSON を走査し、PrimaryID をキーに各ソースの advisory を 1 レコードへフィールド単位で semantic merge する。

関連: `docs/SYSTEM_OVERVIEW.md`、`docs/ROADMAP.md` (Phase 1)

## 1. ゴール

- fetch 済みディレクトリを walk して `map[PrimaryID][]IndexEntry` の索引を作る (Stage 1)。
- 索引を元に各ファイルを full parse し、フィールド単位で semantic merge した UnifiedAdvisory を構築する (Stage 2)。
- UnifiedAdvisory を PrimaryID 別の JSON ファイルとして書き出す (Stage 3)。
- CVE-ID を持たない advisory (AlmaLinux ALBA-*、Go GO-* など) も保持する。
- Phase 2 (AI 処理) と Phase 3 (DB 投入) の入力となる中間表現を提供する。
- 同じロジックを `wisteria debug` から個別に叩けるようにし、マージルールの妥当性を実データで検証できるようにする。

## 2. 非ゴール

- AI による要約・ラベリング・exploit 解析 (Phase 2)
- PostgreSQL への投入 (Phase 3)
- 増分更新 (毎回フル再構築する)
- OSV / CVE 以外のソース (NVD など)
- 各フィールドの最終正規化 (severity 表記の統一など、Phase 2 で AI に吸収させる)

## 3. 用語

- **Advisory**: 1 ファイル = N 脆弱性レコード。1 つのアドバイザリーが複数の脆弱性 ID を持つことがある (例: 複数 CVE-ID を 1 つの別 ID にまとめる、CVE-ID と GHSA-ID が両方ついている)。
- **CVE-ID**: 統合の第一候補キー。OSV は `aliases` 配列に CVE-ID を含むことがある。CVE5 はファイル名 = CVE-ID で必ず存在する。
- **PrimaryID**: UnifiedAdvisory の主キー。CVE-ID があれば CVE-ID、無ければ source 由来 ID。
- **SourceIDs**: PrimaryID 以外の識別子をすべて並列保持する配列 (GHSA-ID、PYSEC-ID、ALBA-ID 等)。
- **UnifiedAdvisory**: 同一 PrimaryID を持つ複数 advisory をフィールド単位で merge した中間表現。
- **Standalone Advisory**: CVE-ID を持たない advisory。PrimaryID が source 由来 ID になる以外は CVE-ID あり advisory と同じ経路で扱う。

### 3.1 PrimaryID 決定ルール

1. CVE5 ファイル: `cveMetadata.cveId` をそのまま PrimaryID とする。
2. OSV ファイルの `aliases` に CVE-ID が N 個ある場合: N 個それぞれを独立した PrimaryID として扱う。同じ OSV ファイルが N 個の UnifiedAdvisory に出現する。
3. OSV ファイルに CVE-ID alias が無い場合: `id` を PrimaryID とする (standalone)。
4. SourceIDs は PrimaryID 以外の全 alias と OSV `id` を集めて dedup + 辞書順で並べる。

例 (入力 → PrimaryID, SourceIDs):

| 入力 | PrimaryID | SourceIDs |
|---|---|---|
| CVE5 `CVE-2024-0001` | `CVE-2024-0001` | (なし) |
| OSV `PYSEC-2021-872` (aliases: `[CVE-2021-42343, GHSA-hwqr-..., GHSA-j8fq-..., PYSEC-2021-387, PYSEC-2021-871]`) | `CVE-2021-42343` | `[GHSA-hwqr-..., GHSA-j8fq-..., PYSEC-2021-387, PYSEC-2021-871, PYSEC-2021-872]` |
| OSV (aliases: `[CVE-2024-0001, CVE-2024-0002]`) | `CVE-2024-0001` および `CVE-2024-0002` の 2 つの UnifiedAdvisory に展開 | 各々の SourceIDs に相手の CVE-ID と OSV `id` を入れる |
| OSV `ALBA-2019:0973` (aliases なし) | `ALBA-2019:0973` | (なし) |
| OSV `GO-2024-1234` (aliases なし) | `GO-2024-1234` | (なし) |

## 4. キャッシュレイアウト

```
<cache-dir>/
├── sources/                                    ← raw download 先 (fetcher の出力)
│   ├── osv/<ecosystem>/*.json
│   └── cve/cvelistV5-main/cves/<year>/<bucket>/CVE-*.json
└── unified/                                    ← merge 後 (本設計の出力)
    ├── cve/<year>/<CVE-ID>.json                ← PrimaryID が CVE-ID
    └── standalone/<ecosystem>/<id>.json        ← PrimaryID が source 由来 ID
```

- `<year>` は CVE-ID (`CVE-YYYY-NNNN`) から抽出。1 ディレクトリのファイル数を抑え FS / ツール (ls, grep) を実用範囲に保つ。
- `<ecosystem>` は OSV の ecosystem 名そのまま (例: `AlmaLinux`、`Go`、`PyPI`)。スペースは `_` に置換 (`Rocky Linux` → `Rocky_Linux`)。
- 1 PrimaryID = 1 ファイル。毎回フル再構築 (§5.1)。

## 5. パイプライン

```
Stage 1: Walk    → map[PrimaryID][]IndexEntry             (索引のみ。中身は読まない*)
Stage 2: Unify   → []UnifiedAdvisory                      (各 IndexEntry を full parse + semantic merge)
Stage 3: Write   → <cache-dir>/unified/cve/<year>/<CVE-ID>.json
                   <cache-dir>/unified/standalone/<ecosystem>/<id>.json
```

(*) PrimaryID 決定のために OSV の `id` と `aliases` だけは読む。SourceRecord 等の構築はせず、map を作るためだけの軽量読み込み。

3 stage を直列に実行する。各 stage は独立した関数。

### 5.1 増分更新はしない (毎回フル再構築)

unify 実行時は `<cache-dir>/unified` を最初に削除してから書き直す。

理由: 当初 standalone advisory として保存された (例: `GHSA-xxxx`) ものに、後日 `aliases: ["CVE-2024-9999"]` が付くケースがある。差分更新方式や上書き方式だと過去の standalone レコードが消えず二重に残る。フル削除 → フル書き直しなら毎回最新 sources の状態だけを反映できる。

## 6. パッケージ構成 (新規分)

```
internal/
└── unified/
    ├── unified.go              # UnifiedAdvisory, Provenance, IndexEntry などの中核型
    ├── osv/
    │   ├── osv.go              # OSV schema (必要フィールドのみ)
    │   └── osv_test.go
    ├── cve/
    │   ├── cve.go              # CVE5 schema (必要フィールドのみ)
    │   └── cve_test.go
    ├── walker/
    │   ├── walker.go           # Stage 1
    │   └── walker_test.go
    ├── unifier/
    │   ├── unifier.go          # Stage 2
    │   └── unifier_test.go
    ├── writer/
    │   ├── writer.go           # Stage 3
    │   └── writer_test.go
    └── inspect/
        ├── inspect.go          # 観察ヘルパ (フィールド分布集計、サンプル抽出など)
        └── inspect_test.go

cmd/
├── unify.go                    # production: 3 stage を直列実行
└── debug/                      # 観察用サブコマンド (1 サブコマンド = 1 ファイル)
    ├── debug.go                # `wisteria debug` の親コマンド
    ├── index.go                # `wisteria debug index`
    ├── unify.go                # `wisteria debug unify`
    └── fields.go               # `wisteria debug fields`
```

## 7. 主要な型

```go
// internal/unified/unified.go

// SourceKind は upstream の種別を識別する。
type SourceKind string

const (
    SourceOSV SourceKind = "osv"
    SourceCVE SourceKind = "cve"
)

// Provenance は merge 前の出所追跡情報。raw データ本体は <cache-dir>/sources/
// 配下に残っているのでここでは持たない。
type Provenance struct {
    Kind SourceKind `json:"kind"`
    Path string     `json:"path"`           // <cache-dir>/sources/ からの相対 path
    ID   string     `json:"id"`             // OSV の id (PYSEC-...) や CVE-ID 自身
}

// IndexEntry は Stage 1 が 1 ファイル分について返す索引情報。
type IndexEntry struct {
    AbsPath  string     // Stage 2 が読む実パス
    RelPath  string     // sourcesRoot からの相対 path (Provenance.Path に入る)
    Kind     SourceKind // osv | cve
    Source   string     // OSV の ecosystem 名 (例: "AlmaLinux", "PyPI")
    SourceID string     // OSV の id、CVE5 のファイル名 CVE-ID
}

// Reference は merge 済みの参照リンク 1 件。
type Reference struct {
    URL  string   `json:"url"`              // 正規化済み URL
    Tags []string `json:"tags,omitempty"`   // OSV の type, CVE の tags を統合 (dedup 済み)
}

// Description は 1 source 由来の説明文。並列保持する (merge しない)。
type Description struct {
    Lang string     `json:"lang"`
    Text string     `json:"text"`
    From Provenance `json:"from"`
}

// Severity は CVSS など重大度評価 1 件。並列保持し、自明な重複だけ dedup する。
type Severity struct {
    Type   string     `json:"type"`             // 例: "CVSS_V3", "CVSS_V4"
    Score  string     `json:"score,omitempty"`  // base score (例: "9.8")
    Vector string     `json:"vector,omitempty"` // ベクター文字列 (CVSS:3.1/...)
    From   Provenance `json:"from"`
}

// AffectedRecord は 1 source 由来の affected 情報をそのまま保持する。
type AffectedRecord struct {
    From Provenance      `json:"from"`
    OSV  *osv.Affected   `json:"osv,omitempty"`
    CVE  *cve.Affected   `json:"cve,omitempty"`
}

// UnifiedAdvisory は PrimaryID をキーに各 source をフィールド単位で merge した中間表現。
type UnifiedAdvisory struct {
    PrimaryID    string           `json:"primary_id"`
    SourceIDs    []string         `json:"source_ids,omitempty"` // PrimaryID 以外の ID (dedup + 辞書順)
    Descriptions []Description    `json:"descriptions"`         // 並列保持 (lang × source)
    References   []Reference      `json:"references"`           // dedup + 辞書順
    Severities   []Severity       `json:"severities"`           // dedup
    Affected     []AffectedRecord `json:"affected"`             // 並列保持
    Provenances  []Provenance     `json:"provenances"`          // 出所一覧
}
```

OSV / CVE の struct は公式 schema から Phase 1 で必要なフィールドだけ定義する。

- OSV: `id`、`aliases`、`summary`、`details`、`affected[]`、`references[]`、`severity[]`
- CVE5: `cveMetadata.cveId`、`containers.cna.descriptions[]`、`containers.cna.affected[]`、`containers.cna.references[]`、`containers.cna.metrics[]`

## 8. マージルール

### 8.1 ベンダー優先順位 (統一配列)

全フィールド共通の優先度配列を 1 本持つ。各フィールドの並び順 / dedup 時の Provenance 選択で参照する。

```go
// internal/unified/unifier/priority.go
var sourcePriority = []string{
    "cve.mitre",            // CVE5 CNA (≒ ベンダー本人) を最優先
    "osv.RedHat",
    "osv.AlmaLinux",
    "osv.Rocky Linux",
    "osv.SUSE",
    "osv.Ubuntu",
    "osv.Debian",
    "osv.Alpine",
    "osv.GitHub",           // GHSA
    "osv.PyPI",
    "osv.npm",
    "osv.Go",
    // ... 残りは default 優先度 (末尾)
}
```

ベンダー名は `<SourceKind>.<ecosystem>` 形式 (例: `osv.AlmaLinux`)。CVE5 は `cve.mitre` で固定。配列に含まれない source は末尾扱い。

### 8.2 References

- URL を正規化してから dedup
  - 正規化: scheme を小文字化、host を小文字化、末尾 `/` を削除、fragment 削除
  - URL parse は `net/url` を使う
- 並び順: 正規化後 URL の辞書順
- `Tags` は同じ URL に紐づくタグの和集合 (dedup)

### 8.3 Descriptions

- merge せず並列保持
- 並び順: 優先度配列順 → lang のアルファベット順

### 8.4 Severities

- 自明な重複だけ dedup する。評価が違うものは別エントリとして残す。
  - 第一 key: `(Type, Vector)` (Vector が空でないとき)
  - フォールバック key: `(Type, Score)` (Vector が無い古い CVSS など)
- 同じ key で複数 source 由来のものを 1 件に寄せる場合、最優先 source の Provenance を残す
- 並び順: 優先度配列順 → Type 順

### 8.5 Affected

- merge せず並列保持
- 並び順: 優先度配列順 → Provenance.ID 順

### 8.6 マージ実装の方針

- フィールドごとに pure function で書く (`mergeReferences(...) []Reference` 等)
- 各 pure function に table-driven test を書く

## 9. 各 stage の I/F

### Stage 1: Walker

```go
// internal/unified/walker/walker.go
package walker

// Index は sources root 配下を走査し、PrimaryID から該当 IndexEntry 群への索引を返す。
// 1 OSV ファイルが aliases に N 個の CVE-ID を持つ場合、同じ IndexEntry が
// N 個の PrimaryID 配下に重複登録される (§3.1)。
func Index(ctx context.Context, sourcesRoot string) (map[string][]unified.IndexEntry, error)
```

- `<sourcesRoot>/osv/<ecosystem>/*.json`: `id` と `aliases` だけ軽量 unmarshal で取り出す
  - aliases に CVE-ID が N 個あれば、各 CVE-ID 配下に同じ IndexEntry を N 個登録 (§3.1)
  - aliases に CVE-ID が無い (または aliases フィールド自体が無い) record は `id` を PrimaryID にして 1 個登録 (standalone)
- `<sourcesRoot>/cve/cvelistV5-main/cves/**/CVE-*.json`: ファイル名から CVE-ID を抽出 (中身を読まない)
- SourceKind / Source は `<sourcesRoot>/<kind>/<ecosystem>/...` のディレクトリ階層から決定的に取る
- ctx キャンセルを尊重する

### Stage 2: Unifier

production と debug で 2 つの関数を分ける。

```go
// internal/unified/unifier/unifier.go
package unifier

// Unify は索引の各 IndexEntry を full parse し、PrimaryID 単位で semantic merge する。
// production 経路。parse 失敗が 1 件でもあれば error を返して全体を止める。
func Unify(ctx context.Context, index map[string][]unified.IndexEntry) ([]unified.UnifiedAdvisory, error)

// UnifyBestEffort は parse 失敗を logger に流して当該ファイルだけ skip し、
// 残りの merge を続行する。debug 経路から呼ばれる。
// log 形式は path と error を含む 1 行。
func UnifyBestEffort(ctx context.Context, index map[string][]unified.IndexEntry, logger *slog.Logger) ([]unified.UnifiedAdvisory, error)
```

- IndexEntry.Kind / Source / RelPath は Stage 1 で確定済み。Stage 2 では再判定しない
- Provenance.Path には IndexEntry.RelPath をそのまま入れる
- PrimaryID 単位でフィールド別 merge (`mergeReferences`, `mergeSeverities`, ...) を順に適用
- SourceIDs は各 source の `id` および `aliases` のうち PrimaryID 以外をすべて集めて dedup + 辞書順
- production の error メッセージにも path を含める

### Stage 3: Writer

```go
// internal/unified/writer/writer.go
package writer

// Write は records を §4 の出力レイアウトに従って書き出す。
//   - PrimaryID が CVE-ID  → cacheDir/unified/cve/<year>/<CVE-ID>.json
//   - それ以外             → cacheDir/unified/standalone/<ecosystem>/<id>.json
// 書き出し前に cacheDir/unified を rm -rf 相当で削除する (§5.1)。
func Write(ctx context.Context, cacheDir string, records []unified.UnifiedAdvisory) error
```

**削除 guard:**

`outDir = filepath.Join(filepath.Clean(cacheDir), "unified")` を内部で組み立て、削除前に以下を assert。いずれか満たさなければ error 返却。

- `cacheDir` が空文字でないこと
- `cacheDir` が絶対 path であること (`filepath.IsAbs`)
- `outDir` の basename が `"unified"` であること
- `outDir` の絶対 path が `/` ではないこと
- 既存の `outDir` の扱い:
  - 存在しない: OK (初回実行)
  - ディレクトリとして存在: OK (削除して再生成)
  - シンボリックリンクまたは通常ファイルとして存在: error

**書き出し:**

- PrimaryID の形式判定:
  - `CVE-YYYY-NNNN` 正規表現にマッチ → cve バケット、`<year>` は YYYY を抽出
  - それ以外 → standalone バケット、`<ecosystem>` は最優先 Provenance の Source。スペースは `_` に置換
- 出力ディレクトリは事前に `MkdirAll`
- temp file → rename でファイル単位 atomic write
- ファイル名は PrimaryID をそのまま使う。FS で危険な文字 (`/`, `:`) は `_` に置換 (例: `ALBA-2019:0973` → `ALBA-2019_0973.json`)

### Inspect (観察ヘルパ)

`internal/unified/inspect/inspect.go` に置く。debug コマンドから呼ばれる前提で、production パイプラインからは呼ばない。提供する API:

- `FieldStats`: フィールドごとの出現数や値の分布を集計
- `Sample`: ID リストまたはランダム抽出で UnifiedAdvisory を取り出す

詳細シグネチャは PR 7 の実装時に確定する。

## 10. CLI

### Production コマンド

```
wisteria unify --cache-dir <path>
```

- 受け取るのは `--cache-dir` だけ。出力先は `<cache-dir>/unified` 固定。
- 入力ルートは `<cache-dir>/sources` を内部で組み立てる
- `--cache-dir` のデフォルト解決ルールは既存の `fetch` と共通
- parse 失敗時は fail-fast (`unifier.Unify` を呼ぶ)。skip + log の挙動は `wisteria debug unify` を使う

### Debug コマンド (production binary に同梱)

```
wisteria debug index                              # walker.Index を回して map のサイズ/分布を出す
wisteria debug index --id CVE-2024-0001           # 特定 PrimaryID に紐づく path を出す
wisteria debug index --id ALBA-2019:0973          # standalone advisory も同じ --id で叩ける
wisteria debug unify --id CVE-2024-0001           # 特定 PrimaryID をフル parse + merge して stdout に出す
wisteria debug unify --sample 10                  # ランダム 10 件の merge 結果を stdout に出す
wisteria debug fields                             # 全 OSV/CVE のフィールド出現数を集計
wisteria debug fields --kind osv --field aliases  # 特定フィールドの値分布
```

- 親コマンド `cmd/debug/debug.go` から各サブコマンドを登録 (1 サブコマンド = 1 ファイル)
- 重い集計は `--limit` 等を持たせる
- `--id` は PrimaryID (CVE-ID または source 由来 ID 両方を受け付ける)

## 11. テスト戦略 (TDD)

各 stage と各 merge function に testdata fixture を置き、外部 I/O なしで完結させる。

```
internal/unified/testdata/
└── sources/
    ├── osv/
    │   ├── PyPI/PYSEC-2021-872.json   # aliases: [CVE-2021-42343, ...] 複数CVE
    │   ├── npm/GHSA-xxxx.json         # aliases: [CVE-2024-0002]
    │   └── AlmaLinux/ALBA-2019.json   # aliases なし → standalone
    └── cve/cvelistV5-main/cves/2024/0xxx/
        ├── CVE-2024-0001.json
        └── CVE-2024-0002.json
```

検証ケース (table-driven):

- **walker**:
  - 期待 IndexEntry map が返ること
  - CVE-ID なし OSV (ALBA-*) が standalone として PrimaryID = 自身の id で索引に残ること
  - 1 OSV の aliases に複数 CVE-ID がある場合は各 CVE-ID 配下に同じ IndexEntry が登録されること (§3.1)
  - IndexEntry の Kind / Source / RelPath / SourceID が正しく埋まること
- **PrimaryID 決定 (§3.1)**: CVE-ID あり / 無し / 複数 CVE-ID alias / 単一 CVE-ID alias の各ケースを網羅
- **mergeReferences**: 同 URL 別表記の dedup、tags の和集合、辞書順
- **mergeSeverities**: `(Type, Vector)` dedup、Vector 無し時の `(Type, Score)` フォールバック、評価が違う severity が並列保持されること
- **Descriptions / Affected の並列保持**: 入力数 = 出力数、優先度順に並ぶこと
- **SourceIDs**: PrimaryID が含まれないこと、dedup + 辞書順、aliases の他の CVE-ID も入ること
- **unifier**:
  - OSV + CVE 両方ある CVE-ID
  - 片側だけ
  - standalone advisory
  - 1 OSV ファイルが複数 UnifiedAdvisory に出現するケース (alias 複数 CVE)
  - parse 失敗時の挙動: `Unify` (production) は error 返却、`UnifyBestEffort` (debug) は skip + log
- **writer**:
  - cve バケット / standalone バケットそれぞれの path 生成
  - 削除 → 再生成: 事前に `<cache-dir>/unified/` に古いファイルがあっても次回 unify で消えること
  - 初回実行 (`unified/` 不在) で error にならないこと
  - 削除 guard: `cacheDir` が空文字 / 相対 path / `/` のとき error、`unified/` がシンボリックリンク or 通常ファイルのとき error
  - ファイル名エスケープ (`:` 等)
- **debug コマンド**: 主要サブコマンドのスモークテスト (`--id` 指定で例外なく動くか)

## 12. データ実態 (参考)

`./tmp/` 配下を走査して確認した実態:

- OSV ecosystem 数: 47 (`AlmaLinux`、`Alpine`、`PyPI`、`npm` ほか)
- 1 ecosystem 配下のファイル数は数百〜数万のオーダー
- OSV ファイル例 `PyPI/PYSEC-2021-872.json` の aliases: `["CVE-2021-42343", "GHSA-hwqr-f3v9-hwxr", "GHSA-j8fq-86c5-5v2r", "PYSEC-2021-387", "PYSEC-2021-871"]`
- AlmaLinux など distro 系 OSV は aliases フィールド自体を持たないものが多い (例: ALBA-2019:0973)
- CVE5 ファイル: `cveMetadata.cveId` に CVE-ID、`containers.cna.descriptions[]` に説明、`containers.cna.affected[]` に影響範囲

## 13. PR 分割

1. **PR 1 (preparation)**: fetcher の出力先を `<cache-dir>/sources/{osv,cve}/...` に変更
2. **PR 2 (schema)**: `internal/unified/{osv,cve}` schema 型 + unmarshal テスト
3. **PR 3 (walker + PrimaryID)**: `internal/unified/walker` + PrimaryID 決定ロジック (§3.1)
4. **PR 4 (debug 骨格)**: `cmd/debug/` の親コマンド + `debug index` (PR 5/6 のマージルール検証を実データで回せるよう先に刺す)
5. **PR 5 (unifier core)**: 中核型 + References / Severities の merge + `debug unify` 最初の出力
6. **PR 6 (unifier rest)**: Descriptions / Affected の並列保持 + `debug unify` 完成形
7. **PR 7 (inspect + debug fields)**: `internal/unified/inspect` + `wisteria debug fields`
8. **PR 8 (production wiring)**: `internal/unified/writer` + `cmd/unify.go`

各 PR は branch-per-feature 方針に従う。

## 14. 未決定事項

実装中に判断が必要な未決事項。該当 PR で決定し、本ファイルに反映してから本セクションから削除する。

- **§8.1 優先度配列の最終メンバー** (PR 5 で確定): 現在の配列はドラフト。`wisteria debug fields` で実データを観察し、出現する全 ecosystem を網羅した上で順序を確定する。
- **マージルール (§8) の実データ検証** (PR 5/6): References の URL 正規化、Severity dedup key、Description / Affected の並び順を `wisteria debug unify --sample` で実データに当てて妥当性を確認する。想定外パターンが出たら本ファイルを更新する。
- **出力フォーマット**: 1 PrimaryID = 1 JSON ファイルで決定。Phase 3 の bulk load で NDJSON が必要になったら別途検討。
- **CLI コマンド名**: `wisteria unify` で決定。ただし PR 8 着手時に `build` / `aggregate` / `merge` のほうが自然と感じたら再考する。
- **並行性**: 初版は直列実装で決定。PR 8 で全データ処理時間を計測し、許容できないなら `errgroup` + 上限付き並列を後付けする。fetcher と同じ pattern を流用する。
- **Inspect API シグネチャ** (PR 7): `FieldStats` / `Sample` の引数・戻り値は debug コマンドの要求に合わせて確定する。
- **ファイル名エスケープ規則** (PR 8): `:` を `_` に置換する暫定方針。standalone advisory に `:` 以外の危険文字 (`/`, `\`, NUL) が含まれる ID が出現したら拡張する。元 ID は JSON 本体の `primary_id` に保持するので往復可能。
