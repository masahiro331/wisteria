# 設計: DB Driver (外部読み取りインターフェース)

外部の Go プログラムが Wisteria の unified advisory データを読むための pluggable な Driver インターフェースを提供する。データの実体はファイルシステム / KVS / RDB / S3 などに置かれうるため、`database/sql` 風の scheme ベース DSN レジストリでバックエンドを差し替え可能にする。最初の実装はファイルシステムドライバ (`fs` scheme) のみ。

関連: `docs/design/unified-advisory.md`、`docs/SYSTEM_OVERVIEW.md`、`docs/ROADMAP.md`

## 1. ゴール

- 外部 Go プログラムが `github.com/masahiro331/wisteria/pkg/...` を import して unified advisory を読めるようにする。
- ID (PrimaryID または alias) 引きと、ecosystem + パッケージ名による検索を提供する。
- バックエンド (FS / KVS / RDB / S3) を DSN の scheme で差し替えられる registry 構造にする。外部モジュールが独自ドライバを `Register` することもできる。
- ID 引き・パッケージ検索を O(1) ルックアップにするための索引を unify パイプラインの新 Stage 5 で生成する。
- `UnifiedAdvisory` と依存する型を `internal/` から公開パッケージへ移動する (型の二重定義はしない)。

## 2. 非ゴール

- FS 以外のドライバ実装 (S3 / KVS / PostgreSQL)。interface と索引フォーマットだけ将来のドライバに耐える形にする。PostgreSQL ドライバは Phase 3 の成果物。
- 書き込み API。Driver は読み取り専用。
- バージョン範囲の評価。`FindByPackage` は ecosystem + パッケージ名の完全一致で advisory を返すだけで、特定バージョンが affected かの判定は呼び出し側が `Affected` を評価する。
- CVE affected (CNA が書く vendor/product) のパッケージ索引。v1 の packages 索引は OSV の `affected[].package` のみを対象とする。
- 増分更新。索引も unified ツリーと同じく毎回フル再構築する。

## 3. パッケージ構成

```
pkg/advisory/          ← UnifiedAdvisory + リーフ型 (internal/unified から移動)
pkg/advisory/cve/      ← CVE5 スキーマ型 (internal/unified/cve から移動)
pkg/db/                ← Driver interface / Register / Open / sentinel error
pkg/db/fsdb/           ← ファイルシステムドライバ (scheme "fs")
internal/unified/indexer/ ← Stage 5: 索引生成 (パイプライン内部)
```

### 3.1 公開型の移動

`internal/unified/unified.go` のうち、Driver の返り値から到達可能な型を `pkg/advisory` へ移動する:

- `UnifiedAdvisory`, `Provenance`, `Reference`, `Description`, `Severity`, `AffectedRecord`, `KEVRecord`, `EPSSScore`, `ExploitDBRecord`, `SourceKind` (+ `Source*` 定数)

`IndexEntry` は Stage 1 の中間データなので `internal/unified` に残す (`pkg/advisory` を import する)。

`AffectedRecord` が `*cve.Affected` を参照するため、`internal/unified/cve` はパッケージごと `pkg/advisory/cve` へ移動する。`AffectedRecord.OSV` は per-ecosystem 型リファクタ (#93) 以降 `any` であり osv 型を参照しないため、`internal/unified/osv` (と `ecosystem` サブパッケージ) は internal のまま。外部利用者は JSON デコード後の `map[string]any` として OSV affected を読む。`kev` / `epss` / `exploitdb` のパーサ型も `UnifiedAdvisory` から参照されないので internal のまま。

既存ステージ (walker / unifier / writer / annotator / pipeline) と `tools/schema-coverage` は import パスの書き換えのみの機械的リファクタで追従する。

## 4. Driver interface と registry

```go
// pkg/db
package db

var ErrNotFound = errors.New("db: advisory not found")
var ErrUnknownScheme = errors.New("db: unknown driver scheme")

type Driver interface {
	// Find returns every UnifiedAdvisory the given id resolves to.
	// id may be a PrimaryID (CVE-ID or standalone ID) or an alias
	// (GHSA, PYSEC, ...). An alias held by an OSV record with multiple
	// CVE aliases resolves to multiple advisories. Returns ErrNotFound
	// when the id resolves to nothing.
	Find(ctx context.Context, id string) ([]advisory.UnifiedAdvisory, error)

	// FindByPackage returns every UnifiedAdvisory whose OSV affected
	// block matches (ecosystem, name) exactly. No version evaluation.
	// No match returns an empty slice and a nil error. ecosystem is the
	// typed advisory.Ecosystem (constants per known OSV ecosystem;
	// release-qualified keys like "Alpine:v3.17" via WithSuffix).
	FindByPackage(ctx context.Context, ecosystem advisory.Ecosystem, name string) ([]advisory.UnifiedAdvisory, error)

	Close() error
}

type OpenerFunc func(ctx context.Context, dsn string) (Driver, error)

func Register(scheme string, opener OpenerFunc)
func Open(ctx context.Context, dsn string) (Driver, error)
```

- `Open` は DSN を `url.Parse` し、scheme で登録済み opener へ dispatch する。未登録 scheme は `ErrUnknownScheme` を wrap したエラー。
- `Register` は `database/sql` と同じく二重登録と空 scheme を panic にする (プログラミングエラーのため)。ドライバパッケージの `init()` から呼ぶ。
- 利用例:

```go
import (
	"github.com/masahiro331/wisteria/pkg/db"
	_ "github.com/masahiro331/wisteria/pkg/db/fsdb" // register "fs"
)

d, err := db.Open(ctx, "fs:///home/user/.cache/wisteria/unified")
defer d.Close()

advs, err := d.Find(ctx, "GHSA-hwqr-...")           // alias 引き
advs, err = d.Find(ctx, "CVE-2024-1234")             // PrimaryID 直引き
advs, err = d.FindByPackage(ctx, advisory.EcosystemPyPI, "django") // パッケージ検索
```

### 4.1 Find の解決規則

1 つの id が複数の UnifiedAdvisory に解決されるケース (OSV が複数 CVE alias を持つ場合、その GHSA は各 CVE の unified ファイルに出現する) があるため、単一返しの `Get` は置かず `Find` に一本化する。PrimaryID 直引きなら要素 1 のスライスが返る。返り値の順序は PrimaryID の辞書順で決定的にする。

## 5. fsdb ドライバ

```go
// pkg/db/fsdb
func New(fsys fs.FS) *Driver            // unified ルートを指す fs.FS を直接注入
func Open(dir string) (*Driver, error)  // os.DirFS(dir) の糖衣
```

- DSN 形式: `fs:///absolute/path/to/unified`。`url.Parse` 後の `Path` をディレクトリとして `Open` する。相対パス、および `Host` が空でない DSN (`fs://foo/bar` の `foo`) は非対応 (エラー)。
- 内部は `fs.FS` にのみ依存する。S3 や zip を `fs.FS` 化する実装を注入すればツリー形バックエンドは fsdb がそのまま使える。KVS / RDB のような非ツリー型バックエンドは `db.Driver` を別実装する。
- `Find(id)`: `index/ids/<escaped-id>.json` を読み、記載された各レコードパスの unified ファイルを読んで unmarshal する。索引エントリが無ければ `ErrNotFound`。
- 索引ディレクトリ自体が存在しない (Stage 5 未実行の古いツリー) 場合: CVE-ID 形式の id は `cve/<year>/<CVE-ID>.json` の直接パスに fallback し、それ以外の id と `FindByPackage` は「索引がない」旨の明示的エラーを返す。
- `FindByPackage(eco, name)`: `index/packages/<escaped-eco>/<escaped-name>.json` を読み、同様にレコードを読む。索引エントリが無ければ空スライス + nil エラー。
- `Close()` は no-op (nil を返す)。

## 6. 索引 (Stage 5)

### 6.1 レイアウト

```
<cache-dir>/unified/
├── cve/<year>/<CVE-ID>.json                    ← 既存 (Stage 3)
├── standalone/<ecosystem>/<id>.json            ← 既存 (Stage 3)
└── index/                                      ← 新規 (Stage 5)
    ├── meta.json                               ← {"version": 1}
    ├── ids/<escaped-id>.json                   ← ID (PrimaryID + alias) → レコード
    └── packages/<escaped-eco>/<escaped-name>.json ← (ecosystem, name) → レコード
```

- **1 エントリ = 1 ファイル**。既存の per-record ツリーと同じ思想で、メモリに索引をロードせず O(1) の直接ルックアップができ、S3 のオブジェクトキーや KVS のキーへそのまま写像できる。
- エントリの中身は record への参照の配列:

```json
{"records": [{"primary_id": "CVE-2021-42343", "path": "cve/2021/CVE-2021-42343.json"}]}
```

`path` は unified ルートからの相対パスで、Stage 3 writer の出力パスと一致する。`records` は `primary_id` の辞書順。

- `ids/` は **PrimaryID 自身も含む全 ID** を張る。`Find` が PrimaryID と alias を区別せず単一のルックアップで解決でき、standalone ID (`ALBA-*` 等) のファイル位置 (ecosystem ディレクトリ) を driver が知らなくて済む。
- `packages/` のキーは OSV `affected[].package` の `ecosystem` / `name` を verbatim に使う (walker の Source 正規化とは別物。スキャナが照合する値をそのまま使う)。
- ファイル名エスケープ: 動的セグメント (`<escaped-id>`, `<escaped-eco>`, `<escaped-name>`) はすべて `url.PathEscape` する。パッケージ名は `/` を含む (Go modules 等) ため、writer の `_` 置換では衝突しうる。writer の既存エスケープは変更しない。
- `meta.json` の `version` は索引フォーマットの世代。ドライバは未知の version に明示的エラーを返す。

### 6.2 生成

- `internal/unified/indexer` を新設する。Stage 2+3 の fan-out 中に merge 済み `UnifiedAdvisory` から (id → record) と (ecosystem, name → record) のタプルを mutex 保護の in-memory map に集約し (`Collect(rec)`)、Stage 4 完了後に Stage 5 として一括書き出す (`Write(outDir)`)。文字列のみの保持なのでメモリは実用範囲。
- `pipeline.Run` に Stage 5 を追加し、既存と同様に per-stage timing を出力する ("stage 5")。
- 書き出しは writer と同じく temp + rename の per-file atomic。`index/` ディレクトリは書き出し前に `RemoveAll` してフル再構築する。

## 7. エラーハンドリング

- 見つからない ID → `db.ErrNotFound` (`errors.Is` で判定可能)。パッケージ検索のヒットなしはエラーではなく空スライス。
- 未知 scheme の `Open` → `db.ErrUnknownScheme` を wrap したエラー。
- 壊れた索引エントリ / unified ファイルの unmarshal 失敗 → ファイルパスを含むエラーで即時 return (silent skip しない)。
- 索引未生成のツリー → §5 の fallback 規則。

## 8. テスト

- TDD で進める。
- `pkg/db`: Register / Open の registry 挙動 (dispatch、未知 scheme、二重登録 panic、不正 DSN) をテーブル駆動でテスト。
- `pkg/db/fsdb`: `t.TempDir()` に writer + indexer でフィクスチャツリーを構築し、`fstest.MapFS` または `os.DirFS` 経由で Find (PrimaryID / alias / 複数解決 / not found) と FindByPackage (ヒット / ヒットなし / `/` 入りパッケージ名) を検証。索引なしツリーの fallback もテストする。
- `internal/unified/indexer`: merge 済みレコードのフィクスチャ → 出力ツリー (パス、エスケープ、records の順序、meta.json) を検証。
- 型移動のリファクタは既存テスト一式 (`make test`) がグリーンのままであることで担保する。
