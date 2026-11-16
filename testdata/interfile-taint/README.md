# interfile-taint

Positive control for `security.ScanTaint` (`src/security/taint.go`), driven by
`scripts/smoke/interfile-taint.sh`.

Every source file carries a `.fixture` suffix, so nothing that builds, lints or
scans this repository treats this deliberately injectable code as its own; the
smoke restores the real names in a temporary copy
(`scripts/smoke/materialise-fixtures.py`).

Each language directory holds the same three flows of a request parameter into
a SQL string:

| Flow | Single-function scan (ScanSource) | Interfile scan (ScanTaint) |
|---|---|---|
| source and sink in one function | found | found, and dropped as ScanSource's |
| sink in a helper in the same file | not found | reported |
| sink in a helper in another file | not found | reported |

| Directory | What it proves |
|---|---|
| `go/` | `tainted-sql-string` across a function and across a file |
| `java/` | the same for Spring request parameters |
| `js/` | `express-sequelize-injection` across a function and across a `require` |
| `csharp/` | cicd's own `log-forging` and `secret-in-log` rules: request input and a credential into `ILogger`, in one function (ScanSource's, below the default gate), across a function and across a file (ScanTaint's); `.Length` and `ReplaceLineEndings` as negatives |
| `deep/` | a chain five calls deep: not followed at the default depth of 3, which the evidence names as `DEPTH CAPPED`; followed with `--interfile-depth=-1` |

No pinned C# rule is marked interfile upstream, so `csharp/` drives cicd's own
rules into a log call rather than into SQL.
