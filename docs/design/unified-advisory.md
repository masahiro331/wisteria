# 設計: Unified Advisory

Phase 1 で取得した OSV / MITRE CVEListV5 のローカル JSON を walker で走査し、PrimaryID をキーに各ソースの advisory を 1 レコードへフィールド単位で semantic merge する。CISA KEV カタログ / FIRST EPSS スコア / Exploit-DB は別経路で扱い、merge 後の unified ファイルに後付けでアノテートする (Stage 4, §5.2)。

関連: `docs/SYSTEM_OVERVIEW.md`、`docs/ROADMAP.md`

## 1. ゴール

- fetch 済みディレクトリ (OSV / CVE5) を walk して `map[PrimaryID][]IndexEntry` の索引を作る (Stage 1)。
- 索引を元に各ファイルを full parse し、フィールド単位で semantic merge した UnifiedAdvisory を構築する (Stage 2)。
- UnifiedAdvisory を PrimaryID 別の JSON ファイルとして書き出す (Stage 3)。
- 既存 unified ファイルに KEV / EPSS / Exploit-DB シグナルを後付けでアノテートする (Stage 4)。
- CVE-ID を持たない advisory (AlmaLinux ALBA-*、Go GO-* など) も保持する。
- Phase 2 (AI 処理) と Phase 3 (DB 投入) の入力となる中間表現を提供する。
- 同じロジックを `wisteria debug` から個別に叩けるようにし、マージルールの挙動を実データで検証できるようにする。

## 2. 非ゴール

- AI による要約・ラベリング・exploit 解析 (Phase 2)
- PostgreSQL への投入 (Phase 3)
- 増分更新 (毎回フル再構築する)
- OSV / CVE5 / KEV / EPSS / Exploit-DB 以外のソース (NVD など)
- 各フィールドの最終正規化 (severity 表記の統一など、Phase 2 で AI に吸収させる)

## 3. 用語

- **Advisory**: 1 ファイル = N 脆弱性レコード。1 つのアドバイザリーが複数の脆弱性 ID を持つことがある (例: 複数 CVE-ID を 1 つの別 ID にまとめる、CVE-ID と GHSA-ID が両方ついている)。
- **CVE-ID**: 統合の第一候補キー。OSV は `aliases` 配列に CVE-ID を含むことがある。CVE5 はファイル名 = CVE-ID で必ず存在する。KEV カタログ / EPSS スコアの各エントリは CVE-ID を主キーに持つ (KEV: `cveID`、EPSS: CSV `cve` カラム)。
- **PrimaryID**: UnifiedAdvisory の主キー。CVE-ID があれば CVE-ID、無ければ source 由来 ID。
- **SourceIDs**: PrimaryID 以外の識別子をすべて並列保持する配列 (GHSA-ID、PYSEC-ID、ALBA-ID 等)。
- **UnifiedAdvisory**: 同一 PrimaryID を持つ複数 advisory をフィールド単位で merge した中間表現。
- **Standalone Advisory**: CVE-ID を持たない advisory。PrimaryID が source 由来 ID になる以外は CVE-ID あり advisory と同じ経路で扱う。

### 3.1 PrimaryID 決定ルール

1. CVE5 ファイル: `cveMetadata.cveId` をそのまま PrimaryID とする。
2. OSV ファイルの `aliases` に CVE-ID が N 個ある場合: N 個それぞれを独立した PrimaryID として扱う。同じ OSV ファイルが N 個の UnifiedAdvisory に出現する。
3. OSV ファイルに CVE-ID alias が無い場合: `id` を PrimaryID とする (standalone)。
4. SourceIDs は PrimaryID 以外の全 alias と OSV `id` を集めて dedup + 辞書順で並べる。

KEV / EPSS は walker / unifier (Stage 1-3) では扱わない。Stage 4 (Annotate, §5.2) で各カタログを読み、既存 unified ファイルにメタを追記する。これらの CVE-ID は PrimaryID への lookup key としてのみ使い、UnifiedAdvisory.SourceIDs には影響しない。

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
│   ├── cve/cvelistV5-main/cves/<year>/<bucket>/CVE-*.json
│   ├── kev/known_exploited_vulnerabilities.json
│   ├── epss/epss_scores-current.csv           ← gzip 展開後の plain CSV
│   └── exploitdb/files_exploits.csv
└── unified/                                    ← merge 後 (本設計の出力)
    ├── cve/<year>/<CVE-ID>.json                ← PrimaryID が CVE-ID
    └── standalone/<ecosystem>/<id>.json        ← PrimaryID が source 由来 ID
```

- `<year>` は CVE-ID (`CVE-YYYY-NNNN`) から抽出。1 ディレクトリのファイル数を抑え FS / ツール (ls, grep) を実用範囲に保つ。
- `<ecosystem>` は walker が `IndexEntry.Source` に格納する正規化済み値 (例: `AlmaLinux`、`Go`、`PyPI`、`Rocky_Linux`、`Generic`)。upstream の OSV ディレクトリ名のうちスペースを `_` に置換し、`[EMPTY]` は fetcher 側で `Generic` にリネームする。それ以外は verbatim。下流 (writer / unifier) は再正規化しない。
- KEV は単一 JSON ファイル (`known_exploited_vulnerabilities.json`)。fetcher は archive を扱わず GET → 保存のみ。
- EPSS は単一 gzip CSV (`epss_scores-current.csv.gz`) を取得し、download 時に gzip 展開して plain CSV (`epss_scores-current.csv`) として保存する。Stage 4 annotator は `encoding/csv` だけで読める。
- Exploit-DB は単一 CSV ファイル (`files_exploits.csv`)。1 行 = 1 exploit、`codes` カラムで複数 CVE-ID を保持する場合は Stage 4 annotator が CVE 単位に展開する。
- 1 PrimaryID = 1 ファイル。毎回フル再構築 (§5.1)。

## 5. パイプライン

```
Stage 1: Walk     → map[PrimaryID][]IndexEntry            (索引のみ。中身は読まない*)
Stage 2: Unify    → []UnifiedAdvisory                     (各 IndexEntry を full parse + semantic merge)
Stage 3: Write    → <cache-dir>/unified/cve/<year>/<CVE-ID>.json
                    <cache-dir>/unified/standalone/<ecosystem>/<id>.json
Stage 4: Annotate → 既存 unified JSON を読み、KEV / EPSS / Exploit-DB シグナルを
                    `kev` / `epss` / `exploits` フィールドに追記して書き戻す
```

(*) PrimaryID 決定のために OSV の `id` と `aliases` だけは読む。SourceRecord 等の構築はせず、map を作るためだけの軽量読み込み。

4 stage を直列に実行する。各 stage は独立した関数。

### 5.1 増分更新はしない (毎回フル再構築)

unify 実行時は `<cache-dir>/unified` を最初に削除してから書き直す。

理由: 当初 standalone advisory として保存された (例: `GHSA-xxxx`) ものに、後日 `aliases: ["CVE-2024-9999"]` が付くケースがある。差分更新方式や上書き方式だと過去の standalone レコードが消えず二重に残る。フル削除 → フル書き直しなら毎回最新 sources の状態だけを反映できる。

### 5.2 Stage 4: Annotate (KEV / EPSS / Exploit-DB 後付け)

Stage 1-3 が書き出した unified ファイル群に対し、外部シグナル (KEV / EPSS / Exploit-DB) を読み込んで CVE-ID に該当する unified ファイルを開き、対応するフィールドを更新して書き戻す。

- 入力ソース:
  - KEV: `<sourcesRoot>/kev/known_exploited_vulnerabilities.json` (JSON)
  - EPSS: `<sourcesRoot>/epss/epss_scores-current.csv` (download 時に gzip 展開済みの plain CSV)
  - Exploit-DB: `<sourcesRoot>/exploitdb/files_exploits.csv` (1 行 = 1 exploit、`codes` カラムに CVE-ID を 0 個以上)
- 該当 PrimaryID の unified ファイルが存在しない CVE-ID は **silent skip**。各カタログには他 source に観測されていない CVE もありうる前提。これを「シグナルだけの standalone unified」として作るかは未決定 (§12 参照)。
- ファイル更新は plain `os.WriteFile`。Stage 4 はフル再構築の後段で動くため、書き込み中断時は次回 `wisteria unify` が Stage 1-3 から再生成する。
- Stage 4 は Stage 3 への依存があるため、`wisteria unify` は 1-3-4 を直列で回す。Stage 4 内の順序は KEV → EPSS → Exploit-DB (各シグナルは互いに独立、別フィールド)。
- 後付けは Stage 1-3 のフル再構築の後段で行うので、毎回最新カタログを反映できる (差分更新の懸念なし)。

## 6. パッケージ構成

```
internal/
└── unified/
    ├── unified.go              # UnifiedAdvisory, Provenance, IndexEntry などの中核型
    ├── osv/                    # OSV schema (必要フィールドのみ)
    ├── cve/                    # CVE5 schema (必要フィールドのみ)
    ├── kev/                    # KEV schema (catalog + entry)
    ├── epss/                   # EPSS CSV row schema
    ├── exploitdb/              # Exploit-DB CSV row schema (Stage 4 入力)
    ├── walker/                 # Stage 1
    ├── unifier/                # Stage 2 (per-PrimaryID merge + sort helper)
    ├── writer/                 # Stage 3 (atomic write + standalone bucket routing)
    ├── annotator/              # Stage 4 (KEV / EPSS / ExploitDB の後付け)
    └── pipeline/               # Stage 1-4 の直列オーケストレーション

cmd/
├── root.go                     # ルートコマンド + 共通 persistent flag
├── fetch.go                    # `wisteria fetch <source>` (各 fetcher の薄いラッパ)
├── unify.go                    # production: pipeline.Run のシン Cobra ラッパ + pprof
└── debug/                      # 観察用サブコマンド (1 サブコマンド = 1 ファイル)
    ├── debug.go                # `wisteria debug` の親コマンド
    ├── index.go                # `wisteria debug index`
    ├── unify.go                # `wisteria debug unify [--id | --sample N]`
    ├── annotate.go             # `wisteria debug annotate` (Stage 4 のみ再実行)
    └── ai.go                   # `wisteria debug ai summarize` (Phase 2 開発用)
```

## 7. 主要な型

```go
// internal/unified/unified.go

// SourceKind は upstream の種別を識別する。
type SourceKind string

const (
    SourceOSV       SourceKind = "osv"
    SourceCVE       SourceKind = "cve"
    SourceKEV       SourceKind = "kev"
    SourceEPSS      SourceKind = "epss"
    SourceExploitDB SourceKind = "exploitdb"
)

// Provenance は merge 前の出所追跡情報。raw データ本体は <cache-dir>/sources/
// 配下に残っているのでここでは持たない。
type Provenance struct {
    Kind SourceKind `json:"kind"`
    Path string     `json:"path"`           // <cache-dir>/sources/ からの相対 path
    ID   string     `json:"id"`             // OSV の id (PYSEC-...) や CVE-ID 自身
}

// IndexEntry は Stage 1 が 1 ファイル分について返す索引情報。
// Path は sourcesRoot からの相対 path。Stage 2 は filepath.Join(sourcesRoot, Path)
// でファイルを再オープンし、同じ値が Provenance.Path に入る。
type IndexEntry struct {
    Path     string     // sourcesRoot からの相対 path
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

// Weakness は CWE 割り当て 1 件。同一 CWE-ID は dedup する (§8.4b)。
// Name は MITRE CWE カタログの正式タイトルで、どの source が主張したかに
// よらず merge 時に一律付与する (source ごとの自由記述は保持しない)。
// カタログ未収載 ID ("n/a" 等の CNA プレースホルダ) のみ空。
type Weakness struct {
    CWEID string     `json:"cwe_id"`         // 例: "CWE-79"
    Name  string     `json:"name,omitempty"` // MITRE 正式タイトル
    From  Provenance `json:"from"`
}

// AffectedRecord は 1 source 由来の affected 情報をそのまま保持する。
type AffectedRecord struct {
    From Provenance      `json:"from"`
    OSV  *osv.Affected   `json:"osv,omitempty"`
    CVE  *cve.Affected   `json:"cve,omitempty"`
}

// EPSSScore は FIRST EPSS の 1 CVE-ID 分のスコア。
// Stage 4 (Annotate, §5.2) で既存 UnifiedAdvisory に追記される。
// EPSS カタログは CVE-ID 一意 (重複なし前提)。
type EPSSScore struct {
    From       Provenance `json:"from"`
    Score      float64    `json:"score"`        // 0.0〜1.0 の確率
    Percentile float64    `json:"percentile"`   // 0.0〜1.0 の順位
    ScoreDate  string     `json:"score_date"`   // CSV header の score_date (RFC3339)
    ModelVersion string   `json:"model_version,omitempty"` // CSV header の model_version
}

// KEVRecord は KEV カタログの 1 エントリを保持する exploit シグナル。
// Stage 4 (Annotate, §5.2) で既存 UnifiedAdvisory に追記される。
// 同じ CVE-ID に複数 source がある場合でも KEV エントリは 1 件 (CVE-ID 一意)。
type KEVRecord struct {
    From                       Provenance `json:"from"`
    VendorProject              string     `json:"vendor_project,omitempty"`
    Product                    string     `json:"product,omitempty"`
    VulnerabilityName          string     `json:"vulnerability_name,omitempty"`
    DateAdded                  string     `json:"date_added,omitempty"`         // YYYY-MM-DD
    ShortDescription           string     `json:"short_description,omitempty"`
    RequiredAction             string     `json:"required_action,omitempty"`
    DueDate                    string     `json:"due_date,omitempty"`           // YYYY-MM-DD
    KnownRansomwareCampaignUse string     `json:"known_ransomware_campaign_use,omitempty"`
    Notes                      string     `json:"notes,omitempty"`
    CWEs                       []string   `json:"cwes,omitempty"`
}

// ExploitDBRecord は Exploit-DB files_exploits.csv の 1 行分を保持する exploit シグナル。
// 1 CVE-ID が複数の EDB-ID (platform / researcher 違い) を持ちうるため Exploits は slice。
// catalog の行順を保つ (Stage 4 が CSV 順に append)。
type ExploitDBRecord struct {
    From          Provenance `json:"from"`
    ID            int        `json:"id"`               // EDB-ID
    URL           string     `json:"url"`              // https://www.exploit-db.com/exploits/<id>
    Title         string     `json:"title"`            // CSV "description"
    DatePublished string     `json:"date_published"`   // YYYY-MM-DD
    Type          string     `json:"type,omitempty"`
    Platform      string     `json:"platform,omitempty"`
    Verified      bool       `json:"verified"`
}

// UnifiedAdvisory は PrimaryID をキーに各 source をフィールド単位で merge した中間表現。
type UnifiedAdvisory struct {
    PrimaryID    string            `json:"primary_id"`
    SourceIDs    []string          `json:"source_ids,omitempty"`  // PrimaryID 以外の ID (dedup + 辞書順)
    Descriptions []Description     `json:"descriptions"`          // 並列保持 (lang × source)
    References   []Reference       `json:"references"`            // dedup + 辞書順
    Severities   []Severity        `json:"severities"`            // dedup
    Weaknesses   []Weakness        `json:"weaknesses,omitempty"`  // CWE-ID で dedup
    Affected     []AffectedRecord  `json:"affected"`              // 並列保持
    KEV          *KEVRecord        `json:"kev,omitempty"`         // KEV カタログ入りの場合のみ非 nil
    EPSS         *EPSSScore        `json:"epss,omitempty"`        // EPSS スコアがある場合のみ非 nil
    Exploits     []ExploitDBRecord `json:"exploits,omitempty"`    // Exploit-DB エントリ (1 CVE = N EDB-ID)
    Provenances  []Provenance      `json:"provenances"`           // 出所一覧
}
```

OSV / CVE / KEV の struct は **upstream の全フィールドを typed field として明示する** (1 byte も落とさない方針)。`json.RawMessage` の catch-all は使わない。upstream schema に新フィールドが入った場合は struct を追加して対応する。検証は `tools/schema-coverage` (typed parse → re-marshal を interface{} parse → re-marshal と diff、upstream の `null` / `[]` / `{}` / Go zero time string は absent と等価扱い、最大 3 件のサンプル file path を表示) を都度回し、漏れがゼロであることを確認する。

例外として、以下のフィールドは upstream で構造が一定でないため `json.RawMessage` 維持を許容する。新規追加時は本リスト + 該当 schema 定義のコメントに理由を記録する:

- `osv.Record.DatabaseSpecific` (`database_specific`): OSV schema が "free-form JSON object" として明示的に定義する DB 固有 catch-all
- `osv.Affected.EcosystemSpecific` (`affected[].ecosystem_specific`) / `osv.Affected.DatabaseSpecific` (`affected[].database_specific`): OSV schema が同様に free-form として定義 (ecosystem ごとに任意 schema)
- `osv.Range.DatabaseSpecific` (`affected[].ranges[].database_specific`): Range レベルでも同じ catch-all を持つ
- `cve.Container.Source` (`containers.{cna,adp}[].source`): CVE5 spec が `additionalProperties` 相当で free-form。実データでも `{"discovery": "INTERNAL"}` 系と `{"lang": "en", "value": "Reporter Name"}` 系が混在し、安定した typed shape を引けない
- `cve.Container.XGenerator` / `XLegacyV4Record` / `XAffectedList` / `XRedhatCweChain` / `XConverterErrors`: upstream `x_*` 拡張で publisher 固有
- `cve.MetricOther.Content`: SSVC など metric ごとに任意 schema

EPSS は CSV 固定 3 列 (`cve, epss, percentile`)、Exploit-DB は CSV ヘッダ固定で構造が決まりきっているため typed のみ (schema-coverage 対象外)。

直接 typed access するのは下記。これ以外のフィールドも全て typed として保持されているが、パイプラインが値を見るのは下記に限る:

- OSV: `id`、`aliases`、`summary`、`details`、`affected[]`、`references[]`、`severity[]`
- CVE5: `cveMetadata.cveId`、`containers.cna.descriptions[]`、`containers.cna.affected[]`、`containers.cna.references[]`、`containers.cna.metrics[]`、`containers.adp[]` の同フィールド
- KEV: catalog top-level (`title`、`catalogVersion`、`dateReleased`、`count`)、`vulnerabilities[]` 各エントリの全フィールド
- EPSS: header コメント行 (`#model_version:..,score_date:..`) はパース時に header struct に取り込む。CSV body の各データ行を `Score{CVE, EPSS, Percentile}` として保持
- Exploit-DB: CSV header の `id` / `file` / `description` / `date_published` / `type` / `platform` / `verified` / `codes` (CVE-ID 列) を行単位に typed 化

## 8. マージルール

### 8.1 ベンダー優先順位 (統一配列)

全フィールド共通の優先度配列を 1 本持つ。各フィールドの並び順 / dedup 時の Provenance 選択で参照する。

```go
// internal/unified/unifier/priority.go
var sourcePriority = []string{
    "cve.mitre",            // CVE5 CNA (≒ ベンダー本人) を最優先
    "osv.Red_Hat",
    "osv.AlmaLinux",
    "osv.Rocky_Linux",
    "osv.SUSE",
    "osv.Ubuntu",
    "osv.Debian",
    "osv.Alpine",
    "osv.GitHub_Reviewed",  // GHSA
    "osv.PyPI",
    "osv.npm",
    "osv.Go",
    // ... 残りは default 優先度 (末尾)
}
```

ベンダー名は `<SourceKind>.<ecosystem>` 形式 (例: `osv.AlmaLinux`)。`<ecosystem>` は walker が `IndexEntry.Source` に格納する正規化済み値 (スペース → `_`) をそのまま使う (例: OSV ディレクトリ `Red Hat` → tag `osv.Red_Hat`)。CVE5 は `cve.mitre` で固定。配列に含まれない source は末尾扱い。

**現時点ではこの配列はドラフト**。`wisteria debug unify --sample N` で実データを観察し、出現する全 ecosystem を網羅した順序を確定する (`docs/ROADMAP.md` Phase 1 to-decide「Vendor priority array final members」参照)。

KEV / EPSS はベンダー / advisory ではなく exploit シグナルなので優先度配列には入れない。Description / Severity / Reference / Affected の merge には参加せず、UnifiedAdvisory の専用フィールド `KEV *KEVRecord` / `EPSS *EPSSScore` (§7) にだけ載せる。

### 8.2 References

- URL を正規化してから dedup
  - 正規化: scheme を小文字化、host を小文字化、末尾 `/` を削除、fragment 削除
  - URL parse は `net/url` を使う
- 並び順: 正規化後 URL の辞書順
- `Tags` は同じ URL に紐づくタグの和集合 (dedup)

### 8.3 Descriptions

- merge せず並列保持
- 並び順: 優先度配列順 → lang のアルファベット順 → 入力順 (再現性確保のための tie-breaker)
- OSV 由来は `Summary` と `Details` を別エントリとして両方保持する (どちらも空でなければ)。要約 / 本文は意味が違うため後段の AI 要約に両方渡す
- CVE5 は CNA の `containers.cna.descriptions[]` に加え、各 ADP (`containers.adp[].descriptions[]`、CISA Vulnrichment 等) も収集する。ADP 由来は Provenance.ID に `#adp:<providerShortName>` を付けて CNA と区別 (情報量を最大化する方針: 後段 AI で取捨選択する)

### 8.4 Severities

- 自明な重複だけ dedup する。評価が違うものは別エントリとして残す。
  - 第一 key: `(Type, Vector)` (Vector が空でないとき)
  - フォールバック key: `(Type, Score)` (Vector が無い古い CVSS など)
- 同じ key で複数 source 由来のものを 1 件に寄せる場合、最優先 source の Provenance を残す
- 並び順: 優先度配列順 → Type → Vector → Score。末尾 2 項は決定的な tie-breaker (1 つの CVE5 ファイルが `cvssV3_0` と `cvssV3_1` を両方持つケースなど、source rank と Type が一致する複数残存エントリがあっても出力順が再現可能になるように)

### 8.4b Weaknesses (CWE)

- 収集元: CVE5 `containers.{cna,adp}.problemTypes[].descriptions[]` の `cweId` 非空エントリ (ADP は §8.3 と同じ `#adp:<name>` 付き Provenance)、および OSV の typed `database_specific` が持つ CWE リスト (GHSA 系 `cwe_ids`、opam `cwe`)。`osv.OSVRecord` の必須メソッド `CWEIDs()` 経由で取り出す (AffectedAny と同じ compile-checked full coverage 方針)。
- dedup key: **CWE-ID 単独**。severity と違い、複数 source が同じ CWE を主張するのは同一の主張なので、最優先 source のエントリを残す
- `Name` は MITRE CWE カタログ (tools/cwe-catalog で `internal/unified/cwe` に生成、Weakness + Category + View 全収載) から merge 時に一律付与。CVE5 problemTypes の自由記述は **保持しない** — source によって説明文の有無・言い回しが変わると unified の抽象が漏れるため
- 並び順: 優先度配列順 → CWE-ID 辞書順 → 入力順
- KEV の `cwes` は exploit シグナルの一部として `KEVRecord.CWEs` に残し、この merge には参加しない

### 8.5 Affected

- merge せず並列保持。OSV / CVE の affected substructure はそのままポインタで保持する (`AffectedRecord.OSV` または `.CVE`)。version range / package name 形式の差異の reconciliation は後段 (Phase 2 / 3) に委ねる
- 並び順: 優先度配列順 → Provenance.ID → 入力順 (tie-breaker: 1 OSV ファイルが N packages を持つ典型ケースで出力を決定的にするため)
- CVE5 は §8.3 と同じく CNA + 各 ADP を全て収集する。ADP は Provenance.ID 末尾に `#adp:<providerShortName>` を付与

### 8.6 KEV / EPSS / Exploit-DB

KEV / EPSS / Exploit-DB は merge ではなく Stage 4 (Annotate, §5.2) で個別ファイルに直接書き戻す。詳細は Stage 4 の I/F (§9 Stage 4) を参照。

- 一意性: KEV エントリは `cveID` で一意。EPSS は CSV `cve` カラムで一意。Exploit-DB は 1 行 = 1 EDB-ID で一意 (`codes` カラムに書かれた各 CVE-ID 配下に展開する)。
- 既存 `UnifiedAdvisory.KEV` / `EPSS` / `Exploits` がある場合は最新カタログの値で完全置換 (再 annotate は idempotent)。
- カタログに該当 CVE-ID が無い既存 UnifiedAdvisory は対応フィールドを触らない。
- 規模感: EPSS は全 CVE をほぼカバー (~30万件)、KEV は exploit 既知のみ (~1500 件)、Exploit-DB は PoC 公開分のみ。Stage 4 内の順序は KEV → EPSS → Exploit-DB。

### 8.7 マージ実装の方針

- フィールドごとに pure function で書く (`mergeReferences(...) []Reference` 等)
- 各 pure function に table-driven test を書く

## 9. 各 stage の I/F

### Stage 1: Walker

```go
// internal/unified/walker
func Index(ctx context.Context, sourcesRoot string, opts ...Option) (map[string][]unified.IndexEntry, error)
func WithConcurrency(n int) Option
```

- `<sourcesRoot>/osv/<ecosystem>/*.json` を軽量 unmarshal (`id` + `aliases` のみ) して PrimaryID を決定 (§3.1)。OSV パーサ並列度は `WithConcurrency` で制御。
- `<sourcesRoot>/cve/cvelistV5-main/cves/**/CVE-*.json` はファイル名のみ参照 (中身を読まない)。
- KEV / EPSS / ExploitDB は対象外 (Stage 4 で別途読み込む)。
- `IndexEntry.Source` はディスク上の OSV ecosystem ディレクトリ名のうち、空白を `_` に置換したもの (例: `Red Hat` → `Red_Hat`)。fetcher 側で `[EMPTY]` → `Generic` rename も行うため、walker から下流は `Generic` を verbatim に扱う。
- ctx キャンセル尊重。1 ファイルでも parse 失敗があれば全体 abort。

### Stage 2: Unifier

```go
// internal/unified/unifier
func MergePrimary(ctx context.Context, sourcesRoot, primaryID string, entries []unified.IndexEntry) (unified.UnifiedAdvisory, error)
func PriorityRank(source string) int
func SourceTag(kind unified.SourceKind, source string) string
```

- Stage 全体のオーケストレーション (PrimaryID fan-out, error policy, writer hand-off) は `internal/unified/pipeline` 側にある。`unifier` 自体は **1 PrimaryID = 1 関数呼び出し** の純粋な merge ユニット。
- IndexEntry.Kind / Source / Path は Stage 1 確定値、Stage 2 では再判定しない。
- 内部 helper:
  - `mergeReferences` (§8.2)
  - `mergeDescriptions` (§8.3)
  - `mergeSeverities` (§8.4)
  - `mergeAffected` (§8.5)
  - 上記 §8.3 / §8.4 / §8.5 のソートは `stableSortByPriority` ジェネリックヘルパに集約 (priority → caller 指定 secondary key → 入力 index の決定論的並び替え)。
- SourceIDs は各 source の `id` および `aliases` のうち PrimaryID 以外をすべて集めて dedup + 辞書順。
- CVE5 ADP container は CNA と並列の Provenance を作り、ID 末尾に `#adp:<providerShortName>` を付与する。

### Stage 3: Writer

```go
// internal/unified/writer
func OutDir(cacheDir string) (string, error)               // path resolve only, no I/O
func Init(cacheDir string) (string, error)                 // OutDir + dest validation + cache reset
func Reset(cacheDir string) (string, error)                // Init + RemoveAll + MkdirAll
func CVEPath(outDir, cveID string) (string, bool)          // <outDir>/cve/<year>/<CVE-ID>.json
func Write(outDir string, rec unified.UnifiedAdvisory) error
```

- **削除 guard** (`Init` 内): `cacheDir` 非空、絶対化後 `/` でない、`outDir` の basename が `"unified"`、既存 outDir はディレクトリのみ許容 (symlink / 通常ファイルは error)。
- **大量書き込み最適化**: bucket dirs (`unified/cve/<year>/`、`unified/standalone/<ecosystem>/`) は package-level `sync.Map` で MkdirAll 結果をキャッシュ。同一 bucket への 100k+ 書き込みでも syscall 1 回。
- **ルーティング**:
  - PrimaryID が `CVE-YYYY-NNNN` → `unified/cve/<year>/<CVE-ID>.json`
  - それ以外 → `unified/standalone/<ecosystem>/<id>.json` (`<ecosystem>` は record 内 OSV provenance のうち `unifier.PriorityRank` が最も小さいもの)。
- ファイル名: PrimaryID の `:` / `/` を `_` に置換 (例: `ALBA-2019:0973` → `ALBA-2019_0973.json`)。
- 1 ファイル単位で temp file → rename の atomic write。

### Stage 4: Annotator

```go
// internal/unified/annotator
func AnnotateKEV(ctx context.Context, sourcesRoot, outDir string) error
func AnnotateEPSS(ctx context.Context, sourcesRoot, outDir string) error
func AnnotateExploitDB(ctx context.Context, sourcesRoot, outDir string) error
func RunAll(ctx context.Context, sourcesRoot, outDir string, w io.Writer, linePrefix string) error
```

- 各 annotator はそれぞれのカタログを読み、CVE-ID で `<outDir>/cve/<year>/<CVE-ID>.json` に lookup → 該当 unified ファイルがあれば `KEV` / `EPSS` / `Exploits` を上書きして書き戻す。
- 該当 unified ファイルが存在しない CVE-ID は **silent skip**。シグナルだけの UnifiedAdvisory を新規生成するかは未決定 (§12 / `docs/ROADMAP.md` の Phase 1 to-decide「Signal-only UnifiedAdvisory」参照)。
- カタログ自体が存在しない (該当 fetch 未実行) → no-op + nil error (部分 pipeline を許容する)。
- カタログ parse 失敗 → file 名付き error で abort。
- EPSS apply は 4× NumCPU の errgroup で並列実行 (各行が異なる CVE-ID を keys するため衝突しない)。
- `RunAll` は KEV → EPSS → ExploitDB を順次実行し、各 stage の経過時間を `w` に書く。`linePrefix` で出力プレフィックスを変えられる (`pipeline.Run` は `"stage 4 "` を渡し、`wisteria debug annotate` は `""` を渡す)。最初の error で中断。

### Stage 1-4 のオーケストレーション: pipeline

```go
// internal/unified/pipeline
type Options struct{ Concurrency int } // 0 → 4× NumCPU
func Run(ctx context.Context, cacheDir string, opts Options, w io.Writer) error
```

- `Run` は walker.Index → writer.Reset → errgroup-bounded `unifier.MergePrimary → writer.Write` fan-out → `annotator.RunAll` の順に実行。
- メモリ常駐は `Concurrency` 件分の advisory のみ (record 単位 streaming)。
- `wisteria unify` は本パッケージのシン Cobra ラッパ。flag parsing と pprof のみ owned で、ステージング詳細はすべて pipeline 側。

## 10. CLI

### Production コマンド

```
wisteria unify --cache-dir <path> [--concurrency N] [--cpuprofile <file>]
```

- `--cache-dir` の解決ルールは `wisteria fetch` と共通 (override → env → user cache dir)。出力先は `<cache-dir>/unified` 固定。
- `--concurrency`: walker と Stage 2+3 fan-out 共通の上限。0 = 4× NumCPU。
- parse 失敗 1 件で全体 abort (fail-fast)。skip 動作の代替は `wisteria debug unify` 側に持たせる方針。
- Stage 1-3 完了後に Stage 4 (`annotator.RunAll`) を直列で呼ぶ。順序は KEV → EPSS → ExploitDB。各カタログ未取得なら no-op + nil error。

### Debug コマンド (production binary に同梱)

```
wisteria debug index                              # walker.Index の map サイズ/分布を出す
wisteria debug index --id <PrimaryID>             # 特定 PrimaryID に紐づく path を列挙
wisteria debug unify --id <PrimaryID>             # 1 PrimaryID をフル parse + merge → indented JSON
wisteria debug unify --sample N                   # 辞書順先頭 N 件をマージ → NDJSON (§8 検証用)
wisteria debug annotate                           # 既存 unified/ ツリーに対し Stage 4 のみ再実行
wisteria debug ai summarize --id <CVE-ID>         # Phase 2 開発用: AI Summarizer を 1 件叩く (現状 CVE-ID のみ)
wisteria debug ai summarize --from-stdin          # Phase 2 開発用: stdin の UnifiedAdvisory を要約
```

- 親コマンド `cmd/debug/debug.go` から各サブコマンドを登録 (1 サブコマンド = 1 ファイル)。
- `--id` と `--sample` は排他。`debug index` / `debug unify` の `--id` は PrimaryID (CVE-ID または source 由来 ID 両方を受け付ける)。`debug ai summarize --id` は現状 CVE-ID 限定で、standalone PrimaryID lookup は follow-up。
- `debug ai summarize` は provider 選択用に `--provider` (default `ollama`)、`--model`、`--endpoint`、`--think` を持つ。
- 重い集計を持つコマンドが今後増えた場合は `--limit` などで応答時間をコントロールする。

## 11. テスト戦略 (TDD)

各 stage と各 merge function は `t.TempDir()` 上の合成 fixture で外部 I/O なしに pin する。pure function (mergeReferences / mergeSeverities / mergeDescriptions / mergeAffected / stableSortByPriority) は table-driven test で別個に網羅。

主要 contract:

- **walker**: PrimaryID 決定の §3.1 全パターン、`IndexEntry.Source` の空白正規化、parse 失敗時の fail-fast。
- **unifier**: OSV+CVE 両方 / 片方のみ / standalone / OSV alias 複数 CVE-ID / CVE5 ADP container ありのケースを `MergePrimary` に通して JSON 出力を pin。
- **writer**: cve バケット / standalone バケットの path 生成、削除 → 再生成、削除 guard (空文字 / `/` / 非ディレクトリ existing outDir)、ファイル名エスケープ。
- **annotator**: 各 annotator の happy path / 空カタログ / parse 失敗 / RunAll の順序 + linePrefix。
- **pipeline**: Stage 1-4 を end-to-end で叩いて両バケットへの書き込みと Stage 4 反映を確認。
- **debug commands**: 各サブコマンドのスモーク (`--id` / `--sample` / 排他 / 未存在 ID で非 0 exit)。

## 12. 未決定事項

設計判断のうち実データを見てから決める項目は GitHub Issues (label `kind/open-question`) で管理する。決定が出た時点で本設計書に反映し、Issue を閉じる。
