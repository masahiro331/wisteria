# 設計: OSV ecosystem サブパッケージ分離

`internal/unified/osv` 配下に肥大化した 44 エコシステムの `RecordX` ファミリ
(`ecosystem_*.go` 7 ファイル) を、新設する `internal/unified/osv/ecosystem`
サブパッケージへ移し、`osv` 本体を「共有 base 型 + Ecosystem enum + 抽象」だけに
絞る。エコシステム固有のスキーマと、全エコシステム共通の土台を、ディレクトリ階層で
分離するのが狙い。

関連: `docs/design/unified-advisory.md` (§7 typed schema / "1 byte not lost")

## 1. ゴール

- エコシステム固有の `RecordX` / `AffectedX` / `TopX` ファミリを 1 つのサブ
  パッケージに隔離し、`osv` 本体から物理的に分ける。
- 依存方向を `ecosystem → osv` の単方向に保つ (循環 import なし)。
- 振る舞いを一切変えない。parse / marshal の round-trip 結果はビット単位で同一。

## 2. 非ゴール

- 型の追加・削除・スキーマ変更 (これは純粋な移動リファクタ)。
- `AffectedRecord.OSV` の `any` を厳密型へ変える話 (別軸、据え置き)。
- registry / init 自己登録方式の導入 (暗黙依存を嫌うため明示 dispatch を維持)。

## 3. パッケージ構成

### `internal/unified/osv` (本体 / 土台)

- 共有 base 型: `Record`, `AffectedBase`, `RangeBase`, `Severity`, `Reference`,
  `Credit`, `Package`, `Event`。
- `Ecosystem` enum + `ecosystemName` テーブル + `String()` / `Normalized()` /
  `EcosystemFromString()`。
- `OSVRecord` interface (`Base() *Record` + `AffectedAny() []any`)。これは下流
  (unifier) が `osv.OSVRecord` として受ける基盤の抽象なので本体に残す。

### `internal/unified/osv/ecosystem` (新規 / エコシステム具象)

- `ecosystem_*.go` 7 ファイルを移動 (44 の `RecordX` / `AffectedX` / `TopX` /
  `NewRecordX`)。各型は `osv.Record` / `osv.AffectedBase` 等を埋め込む。
- `Parse(eco osv.Ecosystem, r io.Reader) (osv.OSVRecord, error)` と
  `parseDispatch` テーブル (45 の `NewRecordX` を参照)。
- `affectedAny[T]` ヘルパー (各 `RecordX.AffectedAny()` が委譲する)。

## 4. 依存方向

```
ecosystem ──> osv     (単方向)
```

`Parse` / `parseDispatch` を `ecosystem` 側に置くことで、`osv → ecosystem` 方向の
依存が生まれず循環を回避する (C-1 案)。`OSVRecord` interface は `osv` に残るが、
`ecosystem.RecordPyPI` 等が構造的にこれを満たす (Go の暗黙 interface 充足)。

## 5. 外部呼び出し側の変更

| ファイル | 変更 |
| --- | --- |
| `unifier/unifier.go` | `osv.Parse` → `ecosystem.Parse`、import 追加 |
| `unifier/convert.go` | `osv.OSVRecord` は据え置き (本体に残る) |
| `unifier/convert_test.go` | `osv.RecordPyPI` / `osv.AffectedPyPI` → `ecosystem.*` |
| `unifier/affected_test.go` | 同上 (`osv.AffectedAlmaLinux` → `ecosystem.*`) |
| `tools/schema-coverage/main.go` | エコシステム型参照を `ecosystem.` へ |

型 (`osv.AffectedBase`, `osv.Package`) は `osv.` のまま、エコシステム具象
(`ecosystem.AffectedPyPI`) は `ecosystem.` と、呼び出し側は 2 パッケージに分かれる。
これは責務分割の自然な帰結として許容する。

## 6. テスト配置

- `osv_test.go` のうち RecordX / `Parse` / RoundTrip 系 →
  `ecosystem/ecosystem_test.go` へ移動。
- `Ecosystem` enum / `EcosystemFromString` 系 → `osv` に残す。

## 7. 検証

決定済み設計の機械的な移動リファクタであり、新しい振る舞いを足さない。各ステップで
`make test` / `make vet` / golangci-lint がグリーンであること、移動前後でテスト結果が
同一であることをもって完了とする。
