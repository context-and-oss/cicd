# The security doctrine

The rules the `security` module was built against, each measured as a false
pass before it was fixed. They belong with [the engineering doctrine](./doctrine.md);
the module's entry functions, key files and scan scoping are in
[src/security/CLAUDE.md](../../src/security/CLAUDE.md).

## An acceptance nobody can read is indistinguishable from a bug

A vulnerability a team has looked at and decided not to act on is a legitimate
thing. A vulnerability that silently stopped being reported is not, and until
`--vuln-accept` the only mechanism cicd offered produced the second while
meaning the first.

`.trivyignore` drops rows **before Trivy writes the report**, so nothing
downstream can tell the acceptance from a tree where the vulnerability was never
there: the counts are lower, `findings[]` is shorter, the CycloneDX document
carries no trace, and the envelope says nothing at all. This repository proved
the shape on itself. Its own `.trivyignore` accepted CVE-2026-39882 in thirty
lines carrying a named exposure argument, a measurement and a removal
condition — every one of which lived in a file no reader of the evidence ever
saw. The evidence said the scan was clean.

**`--vuln-accept "<id>=<reason>"` accepts the finding and keeps it legible.**
`vulnallow.go` partitions the parsed report: an accepted row leaves the severity
counts, `findings[]` and the gate, and arrives in `warnings[]` as
`security: VULN ACCEPTED — <id> covered N finding(s) … Reason given: "…"`. The
row is still in the CycloneDX document attached to the envelope, and the scan
itself was never narrowed — cicd looked at everything and then said, in the
evidence, what it chose not to fail on.

Four rules, each of which is a way this could have become the thing it replaces:

- **It narrows, never widens.** It can only remove rows a scan already found.
  There is no path by which an acceptance causes something not to be scanned.
- **A reason is mandatory and is not graded.** `parseVulnAcceptance` splits on
  the first `=` and refuses an empty reason, a reason with no letter in it, and
  a bare identifier. cicd does not judge the reason — it has no way to — so the
  disclosure says `cicd does not grade this reason` and quotes it verbatim for a
  human who can.
- **One identifier, no patterns.** `*`, `?` and `[]` are refused with their own
  message, because a pattern is an acceptance of vulnerabilities nobody has read
  yet. Two acceptances of the same identifier with different reasons are refused
  too: one of them is wrong and cicd cannot know which.
- **A stale acceptance is louder than a live one.** An acceptance matching
  nothing in this scan emits `security: VULN ACCEPTANCE UNUSED …`, and the
  disclosures are sorted live-first so the unused ones read as the tail they
  are. That is the removal signal: when the upstream fix lands the line starts
  complaining instead of quietly staying a standing permission.

**The value is ONE string, newline-separated, and neither half of that is
cosmetic.** The flag shipped as a `[]string` and the dogfood run it was built
for died on its own reason: `--vuln-accept "CVE-2026-81871=upstream ships no
fixed version, so cicd cannot pin the fix"` arrived as three acceptances, cut at
every comma, and the second fragment was refused for naming no reason. Dagger
exposes a `[]string` parameter as a pflag `StringSlice`, which CSV-parses its
value — measured against the CLI (v0.20.8) with a probe module: commas split it,
repeating the flag splits each occurrence again, and a value containing a
**newline is truncated at it with no error at all**. A `String` parameter
round-trips both byte for byte, so the whole value arrives intact and
`splitVulnAcceptances` does the cutting where the rule is written down and
tested. The separator is the newline and never the comma — `--license-allow` can
use a comma because it takes identifiers, and this one takes a sentence. The
consequence, stated because it is a real limit: a reason cannot span lines. A
continuation rule was rejected — a line that failed to parse would be swallowed
into the reason above it and the "names no reason" refusal, the loudest thing
this mechanism does, would quietly stop firing.

**The filtered document is not safe to read anything else from.** `ResolvedTypes`
and `Examined` in `readTrivyResult` are derived from the **original** parse, and
`TestFilteringCanHideAnEcosystem` exists to say why: a `Result` whose only
content was accepted vulnerabilities disappears from the filtered document, and
`trivyResolvedTypes` would then report that ecosystem unresolved — an acceptance
manufacturing a non-run, which is this file's founding failure mode reached from
a new direction. Anyone tidying `readTrivyResult` to filter once and read
everything from the result breaks a test that says this.

**`warnings[]` is the only channel, and that is a deliberate choice, not a
shortcut.** `cross-cutting/evidence` drops `genericReport` when it merges, so an
acceptance recorded only in a structured payload field would be exactly as
invisible in `combined-evidence.json` and the PR comment as the `.trivyignore`
entry it replaces. `notify` renders warnings verbatim, so the acceptance and its
reason reach the reviewer.

**And a `.trivyignore` that is still there now says so.** `trivyignore.go` lists
the root of the tree as mounted and, on finding one, emits
`security: SCAN NARROWED BY .trivyignore — …`. It cannot say which identifiers
or why, because the rows are gone before cicd sees them; it says that much, names
the file to go and read, and names `--vuln-accept`. Root only, because that is
the only place Trivy looks, and a directory of the same name is not a file — the
trailing separator Dagger appends is the only thing distinguishing them. A
listing cicd could not take is a warning and not an error: the scan is
unaffected, and only cicd's ability to describe it is.

This repository now uses the mechanism on itself. `.trivyignore` is deleted and
its one entry, plus the MEDIUM sibling that arrived with it, are two lines of a
single `--vuln-accept` value in `.github/workflows/dogfood-precommit.yml`. Both are otel
log exporters at v0.16.0 that Dagger's codegen writes into every module's
`go.mod` as a `replace` line and rewrites on every `dagger develop` — measured in
CAPS-058: v0.20.0 compiles and vets clean, and the next codegen run reverted it,
so a committed bump would make `go.mod` advertise a version the runtime does not
use. The removal condition is a `DAGGER_VERSION` bump whose codegen emits
otel >= 1.43.0, and the mechanism now enforces it: when that lands, both
acceptances go UNUSED and the dogfood run says so.

See [specs/accept-a-vulnerability-in-the-open.md](../../specs/accept-a-vulnerability-in-the-open.md).

## Vulnerability severity comes from Trivy, not from CycloneDX

**CycloneDX cannot express the severity Trivy resolved, so it is not read for
one.** Both scans run `--format json` and then `trivy convert --format cyclonedx`
on that report: one scan, two projections, so the SBOM and the counts can never
describe different runs. Severities and findings come from the native report's
`Severity` field — Trivy's own verdict, the same value its `--severity` filter and
its table output use.

The reason is in the CycloneDX spec, not in Trivy. `vulnerabilities[].ratings[]`
is a list of *per-vendor opinions* with no field marking which one the scanner
chose, and the code here used to take entry zero. Measured against trivy 0.70.0
on `debian:11.6` (205 vulnerabilities):

| severity source | CRITICALs found (of 9) | verdict |
|---|---|---|
| `ratings[0]` | **3** | under-reported 34 findings, raised 1 false CRITICAL |
| `max(ratings)` | 9 | over-reported 93 |
| native `Severity` | 9 | exact |

Three specific reasons entry zero is unrecoverable, each measured:

- **Rating order is database serialisation order, not preference.** `ratings[0]`'s
  vendor was `alma` for 117 of the 205 findings — on a Debian image.
- **The authoritative vendor is often absent from the array entirely.**
  CVE-2023-45853 carries `SeveritySource: "debian"`, and its CycloneDX entry has
  no `debian` rating to read.
- **`properties` is null**, so the verdict is nowhere else in the document either.

`trivy convert --format sarif` is not an escape hatch: SARIF has no severity
vocabulary finer than `error`, so critical and high both land there and
`severityFromSARIFLevel("error")` returns HIGH. Routing vulnerabilities through
SARIF renders every CRITICAL as a HIGH row underneath a CRITICAL count.

Consequences worth keeping in mind when touching this path:

- **`trivy convert` must pin `--severity` too.** It accepts the flag and its `-c`
  still defaults to `trivy.yaml` in the working directory, so pinning only the
  scan leaves a consumer's `severity: [CRITICAL]` free to filter the *converted*
  report — the same gutting `trivyPinnedFlags` exists to stop, one step later.
  `trivyflags_test.go` asserts both pins are identical so they cannot drift.
- **An unrated vulnerability is counted LOW and warned about, never dropped.**
  `UNKNOWN` and `""` matched no case in the old parser, so 7 of debian:11.6's 205
  reached neither the counts nor the total nor any list. Unrated is not low-risk,
  but it is also not invisible, so `trivyWarnings` names how many there are.
- **The module states its findings in `envelope.Findings`.** The aggregator reads
  those as given rather than re-deriving them, for the reasons above. Before that,
  Trivy findings reached no detail list at all — a vulnerability-only failure
  rendered a findings count with an empty table.
- **Counts are per package × CVE, matching the rows.** One CVE affecting three
  packages is three actionable fixes; debian:11.6's 205 CVEs are 364 rows. CI
  cross-checks that count against `sum(len(affects))` in the SBOM, which is the
  arithmetic a ratings-based parser cannot satisfy.

## A scan that could not run must never read as "clean"

Every leg here reports zero findings on a clean tree *and* on a tool that never
executed, so the two must be told apart explicitly. Three rules, each of which
was violated before the false-pass fixes:

- **Trivy needs `--scanners vuln`.** `trivy fs|image --format cyclonedx` switches
  Trivy into SBOM-only mode and *disables security scanning* — it says so in its
  own log. Both `vuln_source.go` and `vuln_image.go` omitted the flag, so the
  CycloneDX report had no `vulnerabilities` key at all and every vulnerability
  scan reported **0**, on every shape, for every consumer. Note the shape of the
  false pass: on a tree *with* dependencies an SBOM-only report still emits
  `"vulnerabilities": []`, so only a non-zero count discriminates a working scan
  from a broken one — key presence does not.
- **Resolve SARIF levels, don't read `result.level`.** SARIF 2.1.0 §3.27.10: an
  absent `result.level` inherits `rules[].defaultConfiguration.level` (falling
  back to `warning`), and §3.27.9 makes a non-`fail` `kind` level `none`. Semgrep
  OSS sets **no** level on any result and carries severity only on the rule, so
  reading `result.level` alone bucketed all SAST at the default — SAST could not
  fail a gate above LOW. `findings.go` (`resolveSARIFLevel`) does this properly.
- **Classify the exit status.** A tool's exit code, stderr and report are the only
  evidence that it ran. `semgrepRunError` treats anything but 0/1 as a non-scan,
  and an exit-zero report with no `runs` as a non-scan too.
- **Read the part of the report where Semgrep says what it skipped.** An exit-0
  run of the SAST engine with well-formed `results` can still have rejected
  hundreds of files: its parser writes one
  `runs[].invocations[].toolExecutionNotifications[]` entry per file it could
  not parse (`descriptor.id: "Syntax error"`) and per rule that ran out of time
  (`"Timeout"`), both level `warning`, and nothing else in the document changes.
  A C# primary constructor rejected by Semgrep OSS 1.161.0's parser could
  therefore sit beside a row saying `FINDINGS, warningsCount 0`, despite the
  parser notifications in the attached document. `semgrepnotifications.go`
  classifies them into one `warnings[]` line and the SAST row's `warningsCount`.
  The engine is now Opengrep, which emits the same notification shape, measured
  on 2.0.0. Three traps: the notification has **no `locations` array** — the
  path is only inside `message.text`, after `Syntax error at line ` or
  `Timeout when running <rule> on `, with a trailing colon; the engine **parses
  partially**, so a file it reported a syntax error for can still carry
  findings, which is why the line says "a floor, not a verdict" and never "zero
  findings" — and under Opengrep an unbalanced brace makes the rejected region
  the whole file, so that floor can be zero; and a file skipped for
  `exceeded_size_limit` (1 MB default) appears **nowhere in the SARIF** — only
  in the JSON output's `paths.skipped`, and only with `--verbose`. It is a
  warning and not an error because the remedy is upstream's parser, not a
  consumer commit, and `--fail-on NONE` cannot clear a non-run. The files
  named are also counted on the row as `Examined.partial`, which notify marks
  `⚠️ partial scan` in the Outcome column. Semgrep OSS had two C# gaps outside
  any count — `record` declarations skipped with **no notification at all**,
  and C# 12–14 syntax a later release still rejected — which is why the engine
  was swapped: [specs/swap-semgrep-for-opengrep.md](../../specs/swap-semgrep-for-opengrep.md).
  Opengrep has a silent bound of its own: its taint fixpoint caps each dataflow
  node at a fixed number of visits and skips it past that, reported nowhere, so
  no count can disclose it. See
  [specs/mark-a-partly-read-scan.md](../../specs/mark-a-partly-read-scan.md) and
  [A tool that ran on part of the input must not read as having run on all of it](doctrine.md#a-tool-that-ran-on-part-of-the-input-must-not-read-as-having-run-on-all-of-it).

One measured notification now has a complete fallback rather than only a
disclosure. `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell`
uses a Bash `metavariable-pattern` over the whole `run:` scalar. Semgrep OSS
1.161.0 **and** 1.162.0 rejected valid `${{ ... }}` expressions, command
substitutions and multiline Markdown there. `runSemgrep` detects that exact
rule name in the first pass's notification, reruns every caller-selected config
with only that rule excluded, and adds a runtime-adapted YAML+regex equivalent.
`semgrep_gha.py` reads its structure and notices from the pinned upstream checkout;
no upstream rule body is embedded. Generation failure or a missing loaded
replacement is a non-run, including on a live-only compatibility rerun. The
successful rerun is the report that leaves the module; a warning says the
substitution happened. Every other syntax notification keeps the ordinary
partial-scan warning — cicd substitutes nothing it has not implemented and
tested. Pinned packs plan the adaptation up front; live packs can trigger the
compatibility rerun. Opengrep 2.0.0 parses the same run blocks without a
notification and reports the upstream rule's findings on them (measured), so
under the current engine the rerun does not fire; the detection stays because it
is keyed on the engine's own notification and costs nothing when silent.
Restoring the upstream rule to the pinned manifests is a rule-set change, not
part of the engine swap. The generated copy remains subject to the upstream
restrictive licence, not Apache-2.0; see [runtime rules licensing](../../THIRD_PARTY_NOTICES.md#default-semgrep-rules--semgrep-rules-license-v10-not-apache-20).
The integration fixture under `testdata/semgrep-github-actions` holds
the three valid parser failures and two real curl-pipe-shell findings. Its
workflows are stored as `*.yml.fixture`, so neither GitHub nor zizmor reads
them as this repository's own; `scripts/smoke/opengrep-github-actions.sh`
materialises them into a git clone, which also proves the engine never sees
the tree's `.git` (Opengrep lists a git project with `git ls-files`, and its
image has no git).

Trivy's vulnerability database is cached in the `cicd-trivy-db` volume
(`trivyCachePath`/`trivyCacheVolume` in `images.go`) so the fixed scan does not
re-download it on every run.

## A pattern scanner's zero is a measurement over its rules, too

`Examined` answers "zero findings over how much?". A pattern scanner needs a
second denominator: zero findings *with what*. The same consumer commit, pinned
Semgrep image (the engine at the time) and `--sast-rulesets p/security-audit` produced sharply different
loaded-rule counts on subsequent scans, while both reports read zero findings
over the same file count. The registry resolves a `p/` name at scan
time, so cicd had pinned the engine and not the rules.

- **The default pack is a git commit, not a registry name.** `semgreppack.go`
  reads `p/security-audit` from `semgrep/semgrep-rules` at a fixed sha, with
  membership frozen in `rules/semgrep-security-audit.txt`; `p/owasp-top-ten`
  and `p/secrets` the same way, at the same sha. A pack is not its files: rules
  a staged file carries that the pack does not are excluded by id. Staging each file at
  `/<dir>/<stem>/` and passing `--config /<top>` reproduces the registry's ids,
  which is what lets the next rule be checked at all.
- **Below the floor is a non-run.** Every manifest id must appear in the SARIF's
  own loaded-rules list (case-insensitively; the engine lowercases the path part of
  six of them). One missing id is `ran=false` at every threshold, never a
  smaller clean result. A scan that loaded no rules is a non-run, pinned or not.
- **What is not pinned says so.** The SAST row's (`opengrep`) `rules` records count,
  per-language split, the pin, and every live registry pack; a live pack also
  adds an `UNPINNED RULES` warning. Trap: a consumer config *path* is not
  unpinned — it is versioned with the commit being scanned — and must not be
  listed as if it were.

Spec: [specs/pin-the-default-sast-rules.md](../../specs/pin-the-default-sast-rules.md).

## Scanning HTML is not scanning its executable JavaScript

The default Semgrep scan counted an HTML evidence template as examined but did
not apply JavaScript rules to its inline scripts. Separately, the page's JSON
embedding test passed while evidence text became executable markup at a later
`innerHTML` sink. The audit/OWASP defaults now include a first-party DOM-text
rule and `semgrep_inline.py` analyses selected inline scripts with the same
pinned engine. Original selection/ignores, locations, rule membership, parser disclosures
and source redaction remain part of the result. An internal inline-pass failure
is a non-run, never a fallback to the ordinary scan's green report.

Trap: a temporary JS filename must not become the finding's location or a second
examined source file, and a data-script block is not JavaScript merely because its
tag is named script. Custom sanitizer names are not evidence of escaping. The
page itself now uses text-safe DOM construction, and HTML-only changes run full
CI rather than a documentation exemption. Scope and regression checks:
[scan-inline-javascript-as-code](../../specs/scan-inline-javascript-as-code.md).

## A compiler-backed scan analysed only what the compiler saw

The .NET security analyzers run inside the compiler, so the `roslyn-analyzers`
leg has to build the consumer's projects. A build's exit status is the wrong
witness both ways. A build can fail after the compile, when the analysis has
already run. A compile can also be skipped (up to date) or fail before the
analyzers start, so the build reports success or failure with no analysis
behind it. The witness is the analyzer log. A project is analysed when one of
its compile logs ran at least one enabled security rule. A compile that
reported a compiler error was analysed over an incomplete program and is
partial. Projects to build with no log from any of them is a non-run.

Three further doors, each closed in `roslyn.go`:

- **A project cicd cannot build is named, not dropped.** Legacy, MAUI and
  workload-only projects stay in `Examined.Total` with a reason. A tree of
  nothing else is skipped, not failed: the consumer cannot clear an error there.
- **The repository's configuration may switch a rule off, not grade it.** A
  disabled security rule is a disclosed `NARROWED RULES` line. The severity
  comes from cicd's table by rule id, never from the level the repository's
  `.editorconfig` set.
- **Only the tree's own code is reported.** Locations outside the scanned
  tree or under `bin/` and `obj/` are dropped and counted. No container path
  reaches the envelope.

Trap: the consumer's MSBuild runs in the scan and could rewrite the log. An
absent log reads as not analysed; a forged one cannot be told apart. A gate
over code the consumer controls cannot close that.
Spec: [analyse-dotnet-with-roslyn](../../specs/analyse-dotnet-with-roslyn.md).

## A workflow zizmor could not parse is not a workflow it audited

`zizmor` audits workflows, composite actions and Dependabot files. A file it
cannot parse is a WARN on stderr and the run still exits 0 with no finding for
it, so the SARIF alone reads a broken workflow exactly like a clean one. The
witness is zizmor's own verbose log: every input it registers and every input
it completes. Registered minus completed is the set not audited, named in a
`PARTIAL SCAN` warning; registered and none completed is a non-run. No input
registered at all (exit 3) is no row: a tree with no workflows has nothing to
audit, and the consumer cannot clear an error there.

Three further doors, each closed in `zizmor.go`:

- **The offline narrowing is named.** The scan runs `--offline`, so the audits
  that ask GitHub's API do not run. `NARROWED AUDITS` lists them from zizmor's
  log line, never from a list cicd keeps.
- **An ignore comment or `zizmor.yml` is disclosed, not trusted.** A second run
  with `--no-config --no-ignores` is the shadow; a finding only it has goes
  back in as an accepted suppression, uncounted, and is named in a warning.
  The same rule as the gitleaks shadow.
- **One grade is cicd's.** zizmor rates `unpinned-uses` High for every action
  referenced by tag, which is nearly every consumer's workflow on day one. A
  gate the consumer cannot clear gets switched off, so cicd grades it MEDIUM.
  Every other audit keeps zizmor's severity.

Trap: zizmor does not read `.semgrepignore` and has no path exclusion. A
directory of deliberately unsafe workflows is excluded through `exclude`,
which the evidence names, or stored under a name zizmor does not collect, as
this repository's fixtures are.
Spec: [audit-github-actions-with-zizmor](../../specs/audit-github-actions-with-zizmor.md).

## A taint search that stopped at its depth is not one that followed every call

`ScanTaint` runs Opengrep's interfile analysis, which follows a source through
calls into other functions and files, but only so many calls deep. Past that
depth the engine stops and reports nothing about the chain it did not follow,
so a five-call path from a request parameter to SQL reads exactly like code
with no such path. The witness is Opengrep's own notification: a
`SemgrepWarning` naming the rule and the depth. cicd turns it into a
`DEPTH CAPPED` warning naming each rule, and `--interfile-depth=-1` removes
the limit. A rule whose interfile budget ran out names no file, because the
analysis spans every file; it is a `PARTIAL SCAN` over the whole program, not
a file read in part.

Three further doors, each closed in `taint.go`:

- **Advisory is a threshold, not an exemption.** Warn mode lowers the
  effective threshold to `NONE`, as `ScanLicenses` does, so it passes over
  findings and never over a run that did not complete. An engine killed for
  memory (exit 137, named as such) is an error at every setting.
- **One defect is counted once.** The same rules run without interfile
  analysis, and only what the interfile run adds is reported, by a multiset on
  (rule, file, line, column); `ScanSource` already reports the rest. A failed
  baseline is an error, and the unfiltered findings are kept beside it rather
  than dropped.
- **A depth Opengrep cannot parse is a non-run, not a deeper search.**
  `--interfile-depth -1` as two arguments is an unknown option to Opengrep's
  parser and exits 2; cicd passes `--interfile-depth=N` as one.

Trap: no pinned C# rule is marked interfile upstream, so the step adds nothing
for C#, and every run says so. Cross-method flow in .NET is the Roslyn leg's.
Spec: [report-cross-file-taint-as-advice](../../specs/report-cross-file-taint-as-advice.md).

## A dependency scan that resolved nothing is not a clean dependency scan

The same failure class as the section above, arriving through a missing **input**
rather than a missing flag or a crashed binary — and the purest instance of it,
because nothing at all goes wrong. Trivy runs, exits 0, writes a structurally
valid report, and `Results` is not null. There is no exit status to classify and
no stderr to read.

Trivy resolves .NET dependencies only from `packages.lock.json`,
`packages.config` or a `*.deps.json`. NuGet writes none of those unless a project
sets `RestorePackagesWithLockFile`, so a repository of twenty `.csproj` files
routinely commits no NuGet graph at all — and a filesystem scan of that tree
reports **zero vulnerabilities** and a CycloneDX document with **no .NET
components**. Both are byte-identical to what a genuinely clean .NET repository
produces.

The reason it survived is that it hides best in the repositories most worth
scanning. On a *pure* .NET tree `parseTrivyNative` already errors — Trivy finds no
targets at all and reports `"Results": null`. It takes a **mixed** repository for
the report to look normal: in a mixed .NET/npm tree, the npm lockfiles were
scanned, the SBOM was a valid npm-only SBOM,
the count was real, and the whole C# supply chain was simply absent from a green
verdict. Every consumer-facing signal agreed.

A tree with no supported dependency marker or input is the inverse case. The
independent probe proves there is no dependency scope, so `"Results": null` is
classified as a passing `SKIPPED`, never `CLEAN`: the dependency-vulnerability
and source-SBOM rows each carry their own NOT APPLICABLE warning and neither
claims an examined count. The typed `errTrivyNoTargets` is the only report error
eligible for that classification; an empty, malformed or unreadable report is
still an error, as is a probe that could not establish the tree's scope.

The probe finding a lockfile is not yet proof the lockfile was unreadable:
Trivy leaves development dependencies out, so a lockfile holding only those
produces the same `"Results": null` as one Trivy could not parse. cicd reruns
with development dependencies included; when every package it resolves is
flagged development, the row is `CLEAN` over zero runtime packages with a
`RUNTIME SET EMPTY` warning that names the development vulnerabilities without
gating them. Anything else keeps the error, with the remedy
([spec](../../specs/clear-a-development-only-lockfile.md)).

The licence scan has the same shape one field over: zero licence declarations
read is not zero outside the policy. A completed licence scan that read none is
`SKIPPED`, never `CLEAN`, and names the dependency inputs it could not read.
For .NET, cicd clears it — a lockfile names versions, not licences, so the
licence leg restores the NuGet graph for every .NET tree and Trivy reads each
`.nuspec`, snapshotted inside the restore exec so a pruned cache cannot hand it
an empty folder. A restore that fails is an `ERROR`, never a smaller `SKIPPED`
([spec](../../specs/read-nuget-licences-and-skip-a-licence-scan-that-read-nothing.md)).
For Go, cicd clears it the same way: the licence leg downloads every module the
go.mod files require from the Go module proxy, and only from it, and snapshots
each module's top-level files inside that exec for Trivy to read. A module the
proxy does not serve — every private module — is named as not downloaded,
because cicd has no Go credential input; a download whose own outcome cicd
cannot state is an `ERROR`
([spec](../../specs/read-go-dependency-licences-from-a-downloaded-module-graph.md)).

So `runTrivyFS` reconciles: every ecosystem the tree **declares** against every
ecosystem Trivy **resolved a dependency graph from**. A declared ecosystem that
resolved nothing is a non-run *for that ecosystem* — one `errors[]` entry, and
`passed=false` through `gatedPassed(ran, severityOK, threshold)`, so it fails at
every threshold including `--fail-on NONE`. The table, the matcher and the
messages are in `ecosystems.go`, untagged, so `make test-module-units` runs their
tests.

**The verdict is built on the resolvable input, not on the empty output.** This is
the load-bearing design decision, because the inverse false alarm is just as
damaging as the false pass: a genuinely dependency-free project exists, and a
check that fails it gets switched off within a week — at which point the original
hole is back, with a config flag in front of it. Three conditions must all hold,
and only the first two can accuse:

1. a marker file is present (`*.csproj`, `package.json`, `pyproject.toml`, …) —
   the ecosystem is in this repository;
2. **no resolvable input is present anywhere in the scanned tree** — cicd can
   *see* that Trivy had nothing to read, rather than inferring it from silence;
3. Trivy reported no resolved packages for that ecosystem either.

Condition 3 can only ever **exculpate**. It exists for graphs Trivy resolves from
something that is on no lockfile list — a committed `node_modules`, a vendored
dependency directory — and it is never allowed to *create* a report, because "the
report was empty" is precisely the signal that cannot tell the two states apart.
`trivyResolvedTypes` is correspondingly strict: a `Result` must carry at least one
package or one vulnerability, since an empty result is Trivy naming an ecosystem
it could not read.

**The remedy is part of the fix.** Each message states the fact, says why zero is
not a clean verdict, names up to three of the marker files it found, names the
filenames that would count as a resolvable input, and gives the command
(`dotnet restore --use-lock-file` plus the `RestorePackagesWithLockFile` property,
`poetry lock`, the lockfile npm already writes). A gate whose message a consumer
cannot act on gets suppressed rather than fixed, so the remedy is asserted in the
unit suite for every table entry.

**The probe runs in alpine, not in Trivy's image, and swallows nothing.** Its job
is to check Trivy's silence against an independent reading of the tree, and a
probe sharing the suspect's container shares its failure modes. `find`'s exit
status, stdout and stderr each go to a file and are classified in Go
(`dependencyProbeRunError`) — deliberately *not* the `2>/dev/null || true` that
`quality`'s marker probe uses, because a probe that could not walk the tree leaves
"which ecosystems are here" **unknown**, and unknown must fail the gate rather
than quietly agree that nothing is here. Importing this module's founding false
pass through the checker's own error handling would be the joke writing itself.
There is also no `-maxdepth`: a depth limit shallower than Trivy's own walk would
*manufacture* the false alarm, by missing a lockfile Trivy did read.

**It is fixed as a class, not as the .NET instance that exposed it.** Any ecosystem
whose dependency declaration is not itself a file Trivy can resolve has the same
hole, and a table costs the same as a special case:

| ecosystem | marker | resolvable input | gap |
|---|---|---|---|
| dotnet | `*.csproj`, `*.fsproj`, `*.vbproj`, `*.sln`, `*.slnx` | `packages.lock.json`, `packages.config`, `*.deps.json` | wide — opt-in, so the default is unscanned |
| node | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, … | real — a gitignored lockfile |
| python | `pyproject.toml`, `setup.py` | `requirements.txt`, `poetry.lock`, `uv.lock`, … | real — declare in one file, lock in another |
| go | `go.mod` | `go.mod` | **none** — marker and input are the same file |

Go is structurally immune and is listed anyway, so the immunity is a stated
property with a test (`TestGoEcosystemCannotFire`) rather than an omission
somebody later reads as an oversight. The `.NET` marker set is deliberately wider
than `src/internal/detect`'s: F# and VB projects declare NuGet dependencies
identically, and an unscanned F# supply chain is exactly as unscanned as a C# one.
The question here is *was NuGet resolved*, not *which linter to run*.

A solution file is a marker that only lists other markers, and declares no
package of its own. A tree whose only .NET files are `.sln`/`.slnx` therefore has
no graph to miss: neither restore runs, the ecosystem is not reported
unresolved, and both dependency rows carry a `SOLUTION WITHOUT PROJECTS` warning
naming the files instead. Whether the solutions stand alone is read from the
probe, never from the restore, so a project hidden under `bin/` or `obj/` still
reaches the restore and its no-project error. See
[specs/stand-down-on-a-solution-without-projects.md](../../specs/stand-down-on-a-solution-without-projects.md).

**Four limitations, named because nothing detects them automatically:**

- **Presence is checked tree-wide, not per project.** One lockfile among twenty
  projects clears .NET entirely. Pairing each project with a lockfile in its own
  directory needs a model of solution layout, `Directory.Packages.props` and
  multi-targeting that cicd does not have, and would false-alarm on valid
  repositories. `TestUnresolvedEcosystemsLockfileAnywhereClears` pins the coarse
  behaviour so a future change to it is deliberate.
- **Presence is not proof Trivy parsed the file.** A malformed or unsupported-
  schema lockfile clears the check while resolving nothing. Condition 3 catches
  the subset where Trivy resolved *nothing at all* for that ecosystem only if
  there is also no lockfile.
- **A consumer `trivy.yaml` `skip-dirs` narrows Trivy but not the probe.** Markers
  in a skipped directory can raise an alarm about dependencies Trivy was told to
  ignore. The aligned way to narrow scope is `ScanSource`'s `exclude` parameter,
  which removes the directory before both. This repository would have been the
  first false alarm: its own `trivy.yaml` skips `testdata`, whose `dotnet-app`
  fixture had `.csproj` files and no lockfile — which is why that fixture now
  commits real `packages.lock.json` files and sets
  `RestorePackagesWithLockFile`. Those were generated by a real
  `dotnet restore --use-lock-file`, not hand-written: a lock file whose direct
  dependencies match but whose content hashes do not passes NuGet's consistency
  check and then fails restore with `NU1403`, which would have broken
  `src/quality`'s .NET legs instead. Measured: restoring the fixture again does
  not rewrite either file.
- **The ecosystem → Trivy `Type` map is version-coupled**, the same maintenance
  shape `trivyPinnedFlags` already carries. A new lockfile format missing from
  `inputs` produces a loud false alarm; a renamed `Type` only weakens the
  exculpating check, which cannot accuse on its own. Re-read Trivy's supported
  language list when bumping `trivyVersion`.

Finally, the reconciliation error is returned **alongside a populated result**, the
shape `runGitleaks` uses for a failed history leg: the vulnerabilities Trivy did
find in the ecosystems it could read are real and actionable, and discarding them
to report that a *different* ecosystem was unreadable trades a located finding for
a message. `main.go` and `archive.go` already fold a leg error into `errors[]`
while carrying the result independently, so both `ScanSource` and `ScanArchive`
get this without a change to either.

## A gate a consumer cannot clear is a gate that gets switched off

The section above refuses to call a missing .NET dependency graph clean. On its
own that is correct and unfinishable: NuGet writes a lockfile only when a project
sets `RestorePackagesWithLockFile`, so the remedy is a commit in the *consumer's*
repository, in every project file. **A gate whose only remedy is somebody else's
commit gets switched off** — the switch is `--fail-on NONE` plus a shrug, and
then the original hole is back with a config flag in front of it. That is a
slower version of the same false pass.

The graph was never unobtainable, only unasked for. So when the tree declares
.NET and holds no input Trivy can read, `runTrivyFS` restores the graph itself in
a digest-pinned SDK and scans **that** tree. Measured on
`testdata/dotnet-app-nolock` (trivy 0.70.0, `sdk:8.0`):

| state | Trivy report |
|---|---|
| as committed | no `Results` array at all — zero packages, zero vulnerabilities |
| after the restore | 85 NuGet components in an 87-component SBOM, 2 HIGH CVEs, `Type: nuget` |

`nuget` in `trivyResolvedTypes` then satisfies the reconciliation's exculpating
condition 3 exactly as a committed lockfile would — no special-casing.

It is **automatic**: no opt-in flag (one more thing a consumer must know exists
before their scan stops lying to them) and no opt-out flag (a documented way to
restore the silence). The trigger is a fact about the tree, not a preference.

Three properties are load-bearing, each a way this could have become the thing it
removes:

- **The restore never manufactures a pass.** A restore container that does not
  complete is an `errors[]` entry; the scan proceeds over the source as committed
  and lands on the non-run it would have had anyway, now carrying the reason. And
  `dotnetRestoreAttemptedNote` appends *"cicd also attempted to restore the graph
  itself in … and that did not produce one either"* to the unresolved verdict,
  because without it the message reads as though cicd never tried and the first
  thing a consumer does is what cicd already did.
- **A partial restore is a failure.** Nineteen of twenty projects restoring
  leaves nineteen `packages.lock.json` files — a resolvable input — so
  `unresolvedEcosystems` goes quiet and the twentieth project's dependencies are
  absent from a **green** verdict, in a report now full of real findings. So each
  project is restored individually, each exit status is captured separately, and
  any failure is named. One tree-wide `dotnet restore` would have collapsed all
  twenty statuses into one and made this undetectable. The restored tree is still
  scanned when a project failed — the projects that did restore hold actionable
  findings — and the classification is what stops that reading as complete.
- **A restored graph is not a committed graph, and says so.** Versions resolve at
  scan time, so a floating range can build against versions this scan never saw.
  The success path is a **warning**, not silence, naming that gap and the three
  steps that close it. `notify` renders warnings verbatim into the PR comment, so
  the advice reaches a reviewer rather than a log.

**The trigger asks the same table as the verdict.** `dotnetRestoreNeeded` reads
`depEcosystems()` — the markers and inputs `unresolvedEcosystems` reads. A
restore triggered by one list of filenames and judged by another is how a tree
gets restored and still reported unresolved, or judged resolved on a lockfile the
fallback never looked for.

**And the reconciliation still runs against the original probe** — the tree as
committed, not the restored one. Re-probing would let the fallback's own output
clear the check that judges it, so a restore that wrote lockfiles Trivy then
resolved nothing from would go quiet.

Two mechanics bite anyone touching this:

- **`dotnetSDKBase` must stay a `switch` of literal `From()` calls with no
  `default:` arm.** `scripts/check-runtime-image-pins.py` resolves each `From()`
  argument through package constants, and an argument it *cannot* resolve is
  classified as an ADR-004 consumer-resolved toolchain and never failed. So
  `From(dotnetSDKImages[band])` would not fail the pin gate — it would **pass**
  it, by looking like the one thing the gate deliberately exempts, while cicd's
  own tool image went unpinned. The tidier spelling switches the check off. No
  `default:` because substituting an unpinned band would attribute a dependency
  graph to an SDK nobody selected; that is an error instead.
- **The credential preflight runs before any container exists.** `--nuget-token`
  bound for a cleartext `--nuget-feed-url` is refused by
  `feedTransportOK(…, schemeRequired)`. NuGet does not refuse on the consumer's
  behalf — it answers the 401 challenge with Basic auth over whatever transport
  it was given. Dropping the credential instead would surface as a silent 401,
  i.e. "restore failed", naming neither the feed nor the token. The token is a
  Dagger secret referenced as `%NUGET_AUTH_TOKEN%`, and the
  `<packageSourceCredentials>` block is keyed by the source **name** the
  consumer's own `NuGet.config` gives that URL (`nugetSourceNameForFeed`):
  inventing a name declares a second source for the same URL, which breaks any
  `packageSourceMapping` pointing at the real one.

`nugetfeed.go` is a byte-identical copy of `src/quality/nugetfeed.go` — Dagger
modules are isolated and share code by file copy — declared under `synced_files`
in `scripts/repo-inventory.json` and enforced by `check_synced_files` in
`scripts/repo_surface.py`, where a missing copy is a problem rather than a skip.

**Scope, stated so it is not read as wider.** .NET only; the `depEcosystems`
table stays general so node/python are additions rather than rewrites. Source
scans only — `ScanImage` and `build.Sbom` mount no source tree, so a container
layout landing no `.deps.json` still yields a silent zero there. And a repository
that commits a lockfile sees no restore, no warning and no extra container: the
fallback is invisible to the consumers who took the advice.

Rationale, the measured tables and the rejected alternatives are in
[specs/scan-nuget-without-a-lockfile.md](../../specs/scan-nuget-without-a-lockfile.md).

## A TruffleHog finding without a location is not a finding

`buildTrufflehogSARIF` emitted results with **no `locations` array at all**, and
`parseTrufflehogOutput` put `SourceName` in the finding's file. `SourceName` is
not a path — for a filesystem scan it is the literal string
`trufflehog - filesystem`, identical for every result in the run — so every
secret in an image carried the same fake location and no line. The evidence
aggregator keys its dedupe on the whole finding, so three leaked credentials
found by one detector became **one row** under a count of three, and the row is
what a reviewer acts on. The real path and line are in
`SourceMetadata.Data.Filesystem`.

**`line` is a 0-based offset, and it is serialised with `omitempty`.** Measured
against the pinned trufflehog 3.78.0 on three GitHub tokens at known positions:

| secret on file line | reported |
|---|---|
| 3 | `"line": 2` |
| 7 | `"line": 6` |
| 1 | no `line` key at all |

So `trufflehogLocation` increments it — an evidence field named `line` that is
systematically one row high is worse than none, because a reader clicks it — and
reports an absent key as *no line* rather than as line 1, because omitempty makes
offset 0 indistinguishable from a source reporting no offset and the more precise
of two readings is the fabricated one. A first-line secret therefore arrives with
its path and no line.

**Maintenance risk, named because nothing detects it automatically:** that base
is version-coupled. When bumping `trufflehogVersion`, re-measure it — a secret on
line 1 and a secret on line 7 of a fixture, and check what the JSON says — before
trusting the numbers. `trufflehogreport_test.go` pins the *shape* against a
verbatim capture of that stdout, which catches a schema move but cannot catch a
base flip.

Two related rules the same file now holds:

- **Output TruffleHog cannot be parsed from is a run error, not a shorter list.**
  A half-readable stdout is a scan whose result is unknown, and "unknown" must
  never arrive as fewer findings. The `continue`-on-decode-error this replaces was
  also an infinite loop: `json.Decoder` does not advance past a syntax error, so
  `More()` stayed true and `Decode` failed on the same bytes — measured at 47.8M
  iterations in two seconds, a hang rather than a degradation.
- **`Raw` is not mirrored into the result struct.** It is the credential itself.
  Gitleaks needed `--redact` for exactly this reason: a scanner that copies the
  secret into its report copies it into a downloadable build artifact. A field
  that exists is a field someone renders.

The parsing, argument shape and SARIF construction live in `trufflehogreport.go`,
**untagged**, so `make test-module-units` executes their tests. They previously
sat behind `//go:build !unit_test` with the Dagger code, where a green `lint-repo`
said nothing about whether they had run.

## A ZAP that died is not a target with nothing to find

`ScanWeb` disclosed `dast: NO ALERTED URL — the scan completed and no URL
produced an alert` whenever `Readiness.OK && URLsWithAlerts == 0`. The readiness
probe runs **before** ZAP and talks to the application, not to the scanner, so it
answers 200 in both worlds: a target with nothing to find and a ZAP that never
got off the ground look identical in every field that guard read. It is not
hypothetical — this repository's own `composite-smoke-dast` on `main` printed
that sentence seven lines above `zap: did not run (exit 3)` in the same
`comment.md`, and `ZapExitCode` was already sitting four fields above the guard
in `dastPayload`, unread, under a comment saying that discarding it was the
defect the work existed to fix.

`dastPayload.ScanCompleted` now answers it. It is set in exactly one place
(`main.go`, inside the `readiness.OK` branch) and only on the path where ZAP
exited a status `zapRunError` tolerates **and** the report it left behind parsed
— a truncated report written just before a crash satisfies neither, which is why
the flag tracks "we have a scan" rather than "the process exited". It is a plain
`bool`, not a pointer: a run that never reached ZAP has no clean-scan claim to
make, so `false` and "unknown" call for the same silence.

**Why the log tail exists.** `zapFailureDetail` reduces each stream to its last
non-empty line, and on every startup failure measured that line is
`… DaemonBootstrap - ZAP … terminated` — the consequence, identical across
causes. Three failures in two repositories produced three identical messages and
no diagnosis. `zapLogFor` keeps a 16 KiB tail of each stream (cut forward to the
next line boundary, so the first line is never half a line) in
`genericReport.zapLog`, and **only when `ScanCompleted` is false**: a finished
scan's daemon log is tens of thousands of INFO lines about rules that behaved,
and shipping it in every envelope is how a diagnostic becomes scroll.

**`-T` is not what its doc comment said.** `MaxDurationMinutes` was documented as
capping the whole scan. The packaged scans document `-T` as "max time in minutes
to wait for ZAP to start **and the passive scan to run**"; the active scan is not
on that clock, and omitting the flag does not mean "no cap" — `zap-api-scan.py`
passes `timeout = 0` to `wait_for_zap_start`, which falls back to **600
seconds**. Worse, an overrun is quiet: `zap_wait_for_passive_scan` breaks out of
its wait loop, logs `Exceeded passive scan timeout` at DEBUG (which the packaged
scans do not enable) and the run collects whatever alerts it has, producing a
report byte-for-byte indistinguishable from complete passive coverage. So
lowering `-T` to fail faster on a dead daemon would pay for that speed in silent
partial coverage — the exact failure class this section exists to close.
`zapStartAndPassiveBudgetSeconds` therefore only *reports* the effective budget
(`startAndPassiveBudgetSeconds`), and `startAndPassiveBudgetWarning` discloses it
only when nobody chose it (`startAndPassiveBudgetDefaulted`). A caller who passes
`--max-duration-minutes` gets no line, because
`TestWebDisclosureIsSilentWhenThereIsNothingToDisclose` holds the rule that a
line on every run is a line a reader stops seeing.

See [specs/tell-a-dead-zap-from-a-clean-one.md](../../specs/tell-a-dead-zap-from-a-clean-one.md).

### Say how much of the API ZAP reached

**Neither scope field measures the scan.** A scan can publish findings and pass
without touching a declared API path. `urlsWithAlerts` counts URLs that produced an alert, so it is bounded by
the findings and *falls* on a cleaner target; `endpointsFromSpec` is produced by
`fetchAPISpecContents` + `countAPIOperations`, entirely outside ZAP, and is what
cicd asked for. The API SCAN disclosure asserted the comparison had been made
("only the declared operations were requested") and nothing had compared them.

**The measurement was in the streams already.** `parseZAPScope`
(`zapscope.go`) reads `Number of Imported URLs: N` — logged by `zap-api-scan.py`
for the openapi and soap branches only, over `len(zap.core.urls())` for the
*whole* tree, so it includes the target seed and is not the count the import
added — and `Total of N URLs`, printed by all three scans. Called outside the
`ScanCompleted` branch, because an exit 3 carrying `Number of Imported URLs: 1`
says which of two failures happened. Both streams are searched for both
patterns: which file a line lands in is the packaged scan's logging config, not
a fact about the scan.

**Zero is read from the warning, not the total.** The scans branch — `if
num_urls == 0: logging.warning('No URLs found …')` `else: print('Total of …')`
— so the total line can never carry zero. Reading only it would make the value
that matters most the one that is always absent.

**`Examined` is the only field that survives.** `cross-cutting/evidence` drops
`genericReport` and propagates `Examined` verbatim, so `zapExamined` is what
stops the DAST row reading "not stated". `Total` is left unset in api mode on
purpose: it is a denominator in the same unit as `Count`, and operations
over URL paths would render as a coverage percentage between two things that do
not divide.

**The pair is stated, never reconciled.** `apiScanWarning` prints cicd's count
beside ZAP's and says they count different things. Turning the gap into
`errors[]` + `passed: false` needs a comparison across two units and turns a
shadow pipeline red; it is the next change, not this one.

**Every run is capped and the report does not say so.** `zap_tune` calls
`pscan.set_max_alerts_per_rule(10)` unconditionally in all three packaged scans
(`zap-api-scan.py:407`, `zap-baseline.py:557`, `zap-full-scan.py:333`); no flag
disables it. A rule at the cap stops raising alerts, so its share of the finding
list is a floor and a truncated list renders identically to a complete one.
`rulesAtAlertCap` uses equality and not `>=` — a count above the cap means the
cap is not what this build believes, which is the more interesting fact —
and `alertCapWarning` names rules without calling them truncated, because ZAP's
report carries no field saying which rules are passive and ten is a number an
honest rule can reach. The cap is recorded in the payload rather than left a
constant in Go, because a pin bump can move it and an envelope whose reader must
know which image produced it has a shelf life.

**`scopeUnreadWarning` is unreachable on the pinned image by design.** The total
prints on every run unless `-s` is passed, which cicd never does and a consumer
rule config cannot add — so it is a pin-drift detector, and it names
`zapVersion` so the comment says where to look. Silent unless `ScanCompleted`:
a dead scan already has an `errors[]` entry, and reporting its log unreadable
too describes the same silence twice.

### The endpoints ZAP never requested

The counts above answer "how much". They cannot answer "which", and "which" is
the question a clean api-mode result actually turns on: a scan that reached the
swagger surface and none of the API is a scan whose zero findings mean nothing.
A ratio would need a threshold — a document with many methods on few paths is
healthy and looks like a gap — so nothing is divided. `zapURLDumpHook`
(`src/security/zapurls.go`) is mounted with `WithNewFile` at `--hook`, dumps
`zap.core.urls()`, and `reconcileAPIReach` (`src/security/apireach.go`) names
the declared paths that never entered the tree.

**The hook must not be able to fail the scan it measures.** `trigger_hook` runs
inside the packaged scan's own `try`, so an exception escaping a hook is caught
as "Unexpected error", exits 3, and `zapRunError` correctly calls a finished
scan a non-run. Every trigger body swallows its own exceptions and records the
reason in the dump instead.

**The handle is stashed at `zap_tuned`, never `zap_started`.** `zap_common.py`
feeds a hook's return value back to the caller whenever the trigger passed more
than one argument. `zap_started(zap, target)` is two; a hook returning `None`
there would blank the scan's target. `zap_tuned(zap)` is one, and a
one-argument trigger returns the original args regardless.

**Two triggers because one of them is conditional.** `zap_pre_shutdown` is the
last moment the daemon is alive and sits inside the try block, so a mid-scan
failure skips it; `pre_exit` is outside and always runs, which is why the handle
is kept. A dump holding URLs wins over any later attempt — `_have_urls` — while
a dump holding only an error does not. One file with an `error` key, not two
files, because two files have a state where both are absent.

**The dump path is touched by `zapRunScript`.** Reading a path that does not
exist is a Dagger error, and an error is the one answer that cannot be told
apart from "the hook wrote nothing". Touched, empty means exactly that, and
`parseZAPURLDump` says so.

**`{param}` expands to `[^/]+`, never `[^/]*`.** An empty match would make
`/api/tasks/{id}` reached by a request for `/api/tasks/` — an endpoint reported
covered on the strength of a request for its parent collection, a false green in
the one file that exists to prevent one. Literals go through `regexp.QuoteMeta`,
or the dot in `/api/v1.0/tasks` matches anything. Measured on the pinned image:
an integer parameter is requested as a number (`/api/tasks/10`), a string
parameter as its own name (`/api/projects/projectId/members`).

**A path served by another host is not this host's endpoint.** ZAP's site tree
holds every host it proxied. `requestedAPIPaths` takes the target URL and keeps
only same-hostname requests, naming the rest in `OffOrigin` rather than dropping
them. Hostname alone — not scheme, because an http-to-https redirect is the same
app, and not port. A target cicd cannot parse filters nothing: inventing an
origin would turn a complete scan into a reported non-run.

**A concrete declaration beats the template that would also match.**
`reconcileAPIReach` routes each request the way a server would instead of asking
each declared path whether anything matched it. The first version credited both
`/pets/special` and `/pets/{id}` for one request, so a template nobody requested
reported reached. Among templates no precedence is invented — OpenAPI leaves an
ambiguous match to tooling, so both are credited.

**`-O`'s own path is a prefix candidate.** Measured: `-O http://host:8000/service`
makes ZAP request `/service/api/tasks` for a document declaring `/api/tasks`,
and the document never mentions `/service`. `apiReachPrefixes` adds it, ahead of
the document's claims. Without it every consumer whose target URL has a path
gets a fully scanned API reported entirely unreached.

**An unread entry weakens the gap sentence and never silences it.** With
site-tree entries unread, the warning says cicd saw no request rather than that
ZAP made none. Suppressing it would let one malformed entry hide a real gap. The
zero-reached error is unaffected: a floor of zero is still zero.

**The empty server prefix is always tried and always last.** A `servers[]` entry
is what the document claims, never what the deployment does — `-O` replaces the
host and leaves the path alone — so a declared prefix is a candidate, not a
requirement. A `servers[]` URL with a `{template}` host contributes only its
path, or every declared path would be prefixed with a mangled URL and the whole
API reported unreached by cicd's own parsing. Paths are named as the document
wrote them, since a reader has to find them in their own source.

**Zero reached is an error; a partial gap is a warning.** An OpenAPI document
routinely declares paths ZAP's importer legitimately skips, and failing over
those would red a scan that demonstrably ran. Zero is not a point on that scale.
`Extra` — paths ZAP requested that the document does not declare — is kept
because zero reached beside a populated `Extra` is a scan that ran and missed
the API, while zero beside an empty one is a scan that never started.

**Reach is counted in paths; `endpointsFromSpec` counts operations.** The two
are never subtracted from one another, for the same reason `Examined.Total`
stays unset. The lists are bounded (`maxNamedReachPaths`, `maxSentencePaths`)
and each states how many it left out; the counts are whole.

### The document ZAP would not take

The two sections above measure how much of the API a scan reached, and name the
paths it did not. Neither can say **why**, and on a consumer run the why was the
whole story: only seed URLs were imported from a document declaring a substantial
API, yet the scan completed, exited 0 and reported every rule `PASS`.

ZAP had rejected the document. swagger-parser hands snakeyaml a cap of
**3,145,728 code points**, and `SwaggerConverter.parseV2` re-parses the
*expanded* OpenAPI 3 form of a Swagger 2.0 input — so the number is not the
file's size. Slicing the same document demonstrated that a smaller slice
imported while larger slices failed. Reference expansion, including cyclic
`$ref` relationships, can make a modest source document exceed the parser's
code-point limit. The consumer's slice sizes and schema inventory are omitted.

**Why it was green.** `zap-api-scan.py` guards an empty import with
`if len(urls) == 0: raise NoUrlsException()`, and `-O` had already seeded the
site tree with seed URLs. Nonzero is enough to pass that guard. The import's answer is logged at
`logging.debug('Import warnings: ' + str(res))`, which no normal run enables, and
the API's HTTP 400 body reports `bad_external_data` with no useful detail. The only
sentence that explains anything is in ZAP's own `/home/zap/.ZAP/zap.log` — a
third stream cicd captured nothing from.

**`zapYAMLCodePointLimit` raises the cap** to 32 MiB via
`JAVA_TOOL_OPTIONS=-DmaxYamlCodePoints=…`, and the same document then imports
the API URLs rather than leaving only seeds. Not `.ZAP_JVM.properties`, which also works:
`zap.sh` reads that file's first line into `JMEM` **verbatim** and then skips its
own `-Xmx = memory/4` sizing, so the properties file buys a parser cap with a
heap budget nobody chose. `JAVA_TOOL_OPTIONS` is the JVM's own variable, and it
echoes `Picked up JAVA_TOOL_OPTIONS: …` on stderr, so the setting evidences
itself in a stream cicd already keeps. The limit is stated rather than removed:
unbounded turns a pathological document into a hang bounded only by `-T`, while
bounded turns it into an OOM exit, which `zapRunError` already calls a non-run.

**And `zapimport.go` makes the next one say so.** `zapRunScript` greps the daemon
log for the import endpoint and leaves the block, the grep's exit status and
every WARN/ERROR header; `payload.apiImport` carries them, only on a rejection,
and `zapImportError` is an `errors[]` entry. It sits **beside** `apiReachError`,
never instead of it — the reach error is the symptom, this is the cause, and a
document ZAP accepted can still go unreached.

Five traps, each measured:

- **The pattern matches ZAP's API path, never the parser's wording.**
  `/JSON/(openapi|soap|graphql)/action/import` is the surface cicd already calls,
  so it cannot drift without breaking the call. This file classifies *that* an
  import was refused; the reason is quoted verbatim and never parsed.
- **`-A 30` sweeps up the next entry.** A Java stack trace has no knowable
  length; unrelated INFO entries about scan rules behaving normally can follow
  it into the block. A header line survives
  only if grep matched it, a continuation line only if its header did — which
  also keeps a *second* rejection whole.
- **`daemonLevels` rides only on a rejection.** The sentence naming the limit is
  in a separate entry from the rejection, which says only "the OpenAPI
  definition was invalid"; carrying one without the other keeps the symptom and
  drops the cause. A **successful** import can log unrelated WARNs that explain
  nothing, which is what carrying them always would cost.
- **Three answers, not two.** grep's 0/1/2+, plus `127` for a log that is not
  where cicd expected — outside grep's range on purpose. An unfiltered log and an
  unreadable one produce the same silence. The probe failing is a *warning*; the
  document being refused is an *error*.
- **`127` is spelled in shell and read in Go**, because `zapRunScript` is a Go
  constant and `strconv.Itoa` cannot appear in one. `zapRunScript` therefore
  lives in the untagged `zapscript.go`, not in `web.go`, so
  `TestNoLogStatusIsSpelledOnce` can hold the two spellings together.

### Never let ZAP draw its own proxy port

`zapArgs` passes `-P 8090` on every scan in every mode. It closes a real race in
`get_free_port()`. **It is not what fixed the `BindException` this section was
written about** — that was diagnosed wrong, and the correction is the section
after this one. Read both.

Left unset, `zap_common.py` picks the port ZAP's proxy will listen on like this:

```python
def get_free_port():
    while True:
        port = randint(32768, 61000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not (sock.connect_ex(('127.0.0.1', port)) == 0):
            return port
```

It draws a random number, asks whether anything answers on it *at that instant*,
and returns it. **Nothing is ever bound, so nothing is reserved** — and
32768-61000 is the kernel's own ephemeral range (`/proc/sys/net/ipv4/ip_local_port_range`
reads `32768 60999` in the pinned image), the pool every outbound connection and
every bind-to-zero service draws from. `zap-baseline.py` is candid about it:
`# Choose a random 'ephemeral' port and check its available if it wasn't specified with -P option`.

The gap between that probe and the proxy's actual bind is wide. ZAP spends about
thirty seconds auto-updating add-ons first, opening dozens of outbound
connections, and the OAST add-on binds an ephemeral port of its own on the way
(`Started callback service on 0.0.0.0:35627`). Lose the race and ZAP does not
degrade, it exits:

```
30369 WARN  ExtensionNetwork - Failed to start the main proxy: java.net.BindException Address already in use
30369 ERROR CommandLine      - Terminating ZAP, unable to start the main proxy.
34683 INFO  DaemonBootstrap  - ZAP 2.17.0 terminated.
```

The wrapper does not notice the daemon is gone: it spends its whole 600-second
`-T` budget connecting to a corpse and exits 3. cicd reads that correctly — it is
a non-run, with `scanCompleted: false`, `zapExitCode: 3` and an `errors[]` entry,
which is why the failure was legible at all. It is still ten minutes spent on a
scan that had nothing wrong with it.

So pick the port instead of drawing it. Any value below 32768 is immune by
construction: `if port == 0: port = get_free_port()` skips the lottery entirely
once `-P` is given, and the kernel never hands out 8090 as an ephemeral port.

**The last sentence of this paragraph used to be "so nothing in the container can
take it first", and that was false.** ZAP's own main proxy can take it first —
from itself. See the next section. `-P` stays because the draw is a real hole
that nothing else closes, and because a scan should not depend on a random
number; it is no longer claimed to be the fix.

Three traps. **`-P` is universal but `--autooff` is not** — `P:` appears in the
getopt string of all three packaged scans (`zap-baseline.py`, `zap-api-scan.py`,
`zap-full-scan.py`), so unlike the baseline-only flags it is appended before
anything mode-specific. **8080 is the wrong constant** even though it is ZAP's
own default: it is the port most consumer applications listen on, and this module
composes target URLs against consumer ports, so the one collision left would be
between two things cicd wrote. 8090 is also not, as the spec once claimed, "not
a default anything else here reaches for" — the pinned image reserves it in
three places of its own, Webswing among them — but nothing in the scan container
starts them, so the number stands and the reason for it was wrong. And **the `-P`
fix is argued, not observed** — the race is lost intermittently, so no green run
demonstrates it; the assertion that would actually fail on a regression is
`TestTheProxyPortCannotBeDrawnFromTheEphemeralRange`, which refuses any
`zapProxyPort` inside the range `get_free_port()` draws from.

See [specs/stop-losing-the-port-race.md](../../specs/stop-losing-the-port-race.md).

### Stop ZAP downloading the add-on that owns its own socket

The section above pinned a port and called it the fix. It was not. The
`BindException` had nothing to do with which port was chosen, and the two log
lines that say so are **5 ms apart**:

```
30106 INFO  CommandLine      - Add-on downloaded to: /home/zap/.ZAP/plugin/network-beta-0.29.0.zap
30111 WARN  ExtensionNetwork - Failed to start the main proxy: java.net.BindException Address already in use
30112 ERROR CommandLine      - Terminating ZAP, unable to start the main proxy.
```

`network` is the add-on that **owns ZAP's main proxy**. Upgrading it inside the
running daemon reloads `ExtensionNetwork`, and the replacement binds while the
outgoing instance still holds the socket. ZAP collides with itself. That is
port-independent: it happens on 8090 exactly as on a port `get_free_port()` drew.

The upgrade happens because the packaged scans install add-ons into the live
daemon unless `-silent` is in the `-z` options — `zap-baseline.py:434`,
`zap-full-scan.py:289`, and `zap-api-scan.py:349` inline with **no
automation-framework branch to take instead**, so api mode is unconditionally on
the racing path. cicd's own `--autooff` and `--hook` force the baseline script
onto the same branch.

**The pin governed almost nothing.** Measured against the pinned image on
2026-09-16: one baseline scan downloaded **73** add-ons from the marketplace
before it looked at the target, replacing `network-beta-0.28.0` with `0.29.0` and
`pscanrules-release-74` with `75` — neither pinned anywhere. Two runs of the same
image digest therefore ran different scan rules, and a finding that appeared or
vanished between them could not be attributed to anything.

So `-z "-silent"` goes in, and the rules it would cost are put back from a pin:

| run | add-ons downloaded | passive rules |
|---|---|---|
| as shipped | 73 | 67 |
| `-silent` alone | 0 | 61 |
| `-silent` + pinned `pscanrulesBeta-beta-50.zap` | 0 | **67, rule for rule identical** |

The six rules `-silent` alone costs are named in `zapBetaPassiveRules`; 10063
Permissions Policy Header Not Set and 10099 Source Code Disclosure both fired on
the measurement target, so the loss was real and the pin is why this is not a
narrowing that has to be disclosed on every run.

**Four staging answers, not two.** `zapAddOnStageScript` writes `ok`, `missing`,
`mismatch` or `unreadable`, and the split is load-bearing in both directions:
`missing` and `unreadable` are `warnings[]` naming the six rules, `mismatch` is
an `errors[]` entry quoting the digest and the URL, and an unrecognised status
normalises to `missing` so a truncated file can never manufacture an accusation.

The fourth was measured, not foreseen, and it shipped: `sha256sum -c` answers
exit 1 both for wrong bytes and for a file it could not open, Dagger mounts an
HTTP file `0600 root:root`, and the pinned image runs as uid 1000 — so the first
smoke run of this code published **PINNED ADD-ON REJECTED**, an accusation that
GitHub had served different bytes, about an artifact whose digest was correct.
Two fixes: `WithMountedFile` now passes `Owner: zapContainerUser`, and the shell
takes the digest as a *value* (`ADDON_SUM=$(sha256sum …)` plus a `case`) so only
a successful read can accuse.

Three more things worth knowing before touching this:

- **`-silent` travels through `-z`.** The packaged scans test for the literal
  string in the `-z` value rather than taking a flag of their own, and
  `zap_common.py` `shlex.split`s it — so it is one token, and
  `TestEveryModePassesSilent` holds that for all three modes.
- **The add-on is staged in `/tmp` and copied, never mounted into
  `/zap/plugin`.** A mount cannot be removed from inside the container, and the
  one thing that must not happen to an artifact whose digest did not match is for
  it to still be there when ZAP reads the plugin directory.
- **Staging runs before the scan command, and nothing in it may exit non-zero.**
  ZAP reads `/zap/plugin` once, at startup, so an add-on copied in later never
  loads while the status file still says `ok` —
  `TestRunScriptStagesBeforeItScans` holds the order. A scan that could not gain
  six passive rules is still a scan.

### Return scanner evidence by reference, except bounded DAST

Security entry points normally write `evidence.json` into the module runtime's
workdir through `writeEvidenceFile` and return a `File` reference to it.

`WithNewFile` puts the whole JSON document into the returned object's graph ID.
That is small for most source scans, but a ZAP report can include response data
for every request it made. A completed API scan can therefore stall at
`Container.WithNewFile evidence.json` while constructing the returned graph,
until the configured job timeout. The final evidence aggregator already avoids this
shape for the same reason; producers now do too.

DAST is the deliberate exception. Its native ZAP document is compacted first,
the final envelope is refused above 16 MiB, and `writeInlineDASTEvidenceFile`
embeds those bounded bytes in a core Directory. A workdir-backed DAST File kept
the completed scan's module/service graph alive: subsequent trials showed
`Security.scanWeb`, `Dast.scan`, and the terminal File
operation all DONE while the CLI still waited. The value-backed File is the
lifecycle boundary; the 16 MiB guard prevents the original unbounded graph-ID
failure from returning under a new name.

`ScanWeb` also explicitly stops its bound application service with `Kill: true`
after readiness, specification fetch, and ZAP have materialised every result.
The application is disposable at that point; leaving shutdown to session
cleanup let a long-lived consumer service keep the CLI alive after every relevant
trace operation had completed.

The fixed `security-evidence/` directory used by the other scanners is cleared before each write. A module
workdir can survive a prior invocation, and returning a stale envelope is worse
than returning no envelope. See
[specs/return-security-evidence-by-reference.md](../../specs/return-security-evidence-by-reference.md).


## A secrets scan must open what the output ships

`ScanArchive` exists to catch a `.env` bundled into a build output, and on
gitleaks v8.30.1 `--max-archive-depth` defaults to **0**, which opens no archive
at all. cicd passed no value, so an output holding only `app.zip`, with two
credentials inside, logged `scanned ~0 bytes` and `no leaks found`, exited 0 and
passed. Both `dir` legs — `ScanArchive`'s output and `ScanSource`'s
working tree — now pass `gitleaksMaxArchiveDepth` (3); the history leg does not
take the flag. The depth is the only bound on a recursive archive, so it is
never unbounded, and an archive past it is named rather than dropped.

**The depth is half the fix, because gitleaks decides by extension.** It opens
`.zip`, `.tar` and `.tar.gz`, and reads a `.jar`, `.war`, `.nupkg`, `.whl`,
`.vsix`, `.apk`, a `.tgz` or an extensionless zip as an opaque binary at every
depth. The only trace is `DBG skipping binary file mime_type=… path=…`, so the
tree leg runs at `--log-level debug` and `gitleaksarchives.go` turns the lines
whose content type is on `gitleaksArchiveMIME` into one `warnings[]` line, and
the `WRN skipping archive: exceeds max archive depth` lines into another. Both
name the files, sorted, quoted and capped at `gitleaksArchiveNamesShown` with
the count kept whole. A warning, not an error, on the
`semgrepnotifications.go` precedent. The row also gains
`Examined{Unit: "bytes read from the tree"}` from `INF scanned ~N bytes`.

Four traps, each measured:

- **DBG logs decoded file content.** `segment found: "…" -> "…" decoder=…`
  quotes what a decoder produced, so a base64-encoded credential reaches the log
  *decoded*, and `--redact` governs only the report. `gitleaksScript`'s awk
  keeps the skipped-binary shape in `gitleaks.skipped`, drops every other DBG
  line before anything reaches the disk, and passes the rest to `gitleaks.err`
  unchanged so `gitleaksRunError` reads what it always read.
  `TestGitleaksScriptKeepsOnlyTheSkippedBinaryLines` replays a decoded
  credential through the real script and asserts it reaches no file.
- **Match the kept shape on whole fields, never as a substring.** A segment line
  quoting file content that *looks* like the kept line would otherwise route
  that content into `gitleaks.skipped` — the awk tests fields 2–5, the Go regex
  is anchored on the timestamp field.
- **A filter that did not finish fails closed.** The awk writes a sentinel at
  `END`; without it the script records exit 125 and an `errors[]` reason,
  because an unknowable skipped list must not read as "nothing went unopened".
  The script keeps gitleaks' own status, not awk's — a pipeline's status is its
  last command's, and the container shell is dash, with no `pipefail`.
- **The disclosure is wording-coupled.** A gitleaks bump that rewords either
  line silences the warnings and fails nothing in the unit suite. Recapture
  `testdata/gitleaks-8.30.1-dir-archives.stderr` from the new image before
  bumping; `ci.yml`'s security cell, which zips the planted `leaked.env` into
  `app.zip` and `service.jar`, is the integration tripwire.

Residue: an archive under an extension gitleaks' global allowlist skips (a
tarball named `data.bin`) is skipped before sniffing and is not disclosed; a
corrupt archive is skipped silently at every log level; and an archive bomb
costs time, not memory — bounded by the job timeout, not by cicd. Opening
committed archives in `ScanSource` can surface findings a pre-commit gate never
reported before; that is the gate starting to work. See
[specs/open-the-archives-the-output-ships.md](../../specs/open-the-archives-the-output-ships.md).

## A missing `.git` is not a failure; an unreadable one is

`historyAvailable`
requires a `.git/` *directory*, not merely an entry named `.git`. In a git
worktree or submodule `.git` is a file holding an absolute
`gitdir: /path/to/main/.git/worktrees/x` pointer, and that path does not exist
inside the container — demanding history there would fail the gate on a
perfectly valid checkout. Dagger's `Entries()` distinguishes them by the
trailing separator. When `.git/` *is* present, the history leg must prove it
read commits: gitleaks logs the git failure, reports `0 commits scanned`, says
`no leaks found` and still **exits 0**, so the exit status alone can never tell
a broken object store from a clean history. An absent or zero commit count is
an error (`gitleaksRunError`).

## A history-leg failure never discards the tree leg's findings

`runGitleaks`
returns a report *and* an error in that case. The SAST adapter also keeps the
ordinary scan's findings when its later inline pass fails; a failure with no
usable report cannot preserve one. Nulling the result would trade a located, actionable secret
for a message about a different leg; `main.go` appends the error to `errors[]`
(failing the gate) and carries the report independently, so the team gets both.

## Every gitleaks run passes `--redact`

Without it gitleaks writes the
credential it found into `region.snippet.text`, and that SARIF is passed through
into the evidence envelope verbatim — so a secrets scan would copy the secret
into a build artifact downloadable by anyone with repository read access, and
hand it to every consumer of `cross-cutting/report`. Redaction keeps ruleId,
file, line and columns, which is all triage needs; the literal value is in the
developer's own file at that line. The `module-test` cell asserts the raw
fixture key does not survive into the envelope.

Findings are counted from the same SARIF document the envelope carries.
Previously a *second* gitleaks run with `--report-format json` existed purely to
count, and its error was discarded (`if jsonErr == nil`), so a failed counting
run yielded zero findings beside a SARIF that listed them — and the gate
believed the count.

## Semgrep's matched source never reaches the envelope

The SAST engine (Semgrep then, Opengrep now) copies the matched line into every result (`region.snippet.text`), and
the `generic.secrets.*` rules in the default `p/security-audit` match exactly
the line holding a credential — so the key `--redact` kept out of the secrets
leg arrived through SAST. `redactSemgrepSARIF` rewrites every report in
`runSemgrepOnce` before anything reads it: snippets at any depth and `fixes`
are removed, and the result message is replaced with the rule's declared
message, because the engine interpolates metavariables and
`secrets-in-config-file` puts the secret in `$VALUE`. ruleId, location,
suppressions, fingerprints, the rule catalogue and the notifications stay. A
report it cannot read is an error, never passed through.

The notifications are a channel of their own: a `Syntax error` quotes what the
parser rejected between backticks, and for JavaScript that is the whole line,
string literal included (measured on 1.162.0). The `PARTIAL SCAN` warning
repeated it. Everything from the first backtick to the last is now
`[source withheld]`, in the SARIF and in the warning; path, line and the
single-quoted rule id stay. Greedy, because source can hold backticks.

Trap: a fixture cannot prove this. The AWS rule refuses any match containing
`example`, `sample`, `test` or `fake`, which every committed credential carries.
`scripts/smoke/semgrep-redaction.sh` assembles its probe key at run time and
asserts the engine matched it before asserting it is absent. See
[specs/redact-semgrep-snippets.md](../../specs/redact-semgrep-snippets.md).

## A secrets scan withholds who committed, not only what

`--redact` governs the credential, not the person. gitleaks' history leg writes
the commit's author, email and message into each result's
`partialFingerprints` (measured on v8.30.1), and the envelope is downloadable
and uploaded to code scanning. `withholdGitleaksCommitIdentity` keeps only
`commitSha` and `date`, on every leg, as an allowlist: a key a later gitleaks
adds is withheld until reviewed. A report it cannot walk is an error, never
passed through. The sha still resolves to the author for anyone with
repository access; that is the repository's access control, not cicd's
publication. `scripts/smoke/gitleaks-identity.sh` commits a run-time key under
a fictitious identity and deletes it, so only the history leg can report it.
See [specs/withhold-commit-identity-from-secrets-evidence.md](../../specs/withhold-commit-identity-from-secrets-evidence.md).

## A gitleaks suppression is disclosed, never trusted silently

gitleaks drops a finding three ways — an inline `gitleaks:allow`, a
fingerprint in `.gitleaksignore`, a root `.gitleaks.toml` — and writes none of
them into its report, so a pass resting on one read exactly like a clean tree.
This repository's own config proved the worst case: it set only an
`[allowlist]`, which replaces gitleaks' 222 default rules with **none**, and
every scan of cicd searched for nothing. Two rules now hold, both in every
gitleaks leg:

- **Zero loaded rules is a non-run** (`gitleaksRunError`), read from the
  SARIF's `tool.driver.rules`, gitleaks' own record of what it loaded.
- **What a suppression removed is put back, visible and uncounted.** When a
  suppression could apply, the tree leg runs a shadow scan over the tree with
  the config and ignore file removed and `--ignore-gitleaks-allow`. A result
  only the shadow reported is appended with an accepted SARIF suppression,
  which every counter skips, and `warnings[]` gets one `SUPPRESSED` line per
  mechanism naming each `"file:line rule"`. A config that leaves out a default
  rule adds `NARROWED RULES`, naming the rules.

Attribution is measured, not inferred: the `.gitleaksignore` fingerprint from
gitleaks' own DBG line (kept only when it carries `finding=REDACTED`), the mark
from a `grep -rnoF` (`-o`, so no file content leaves the container), the config
only when the mark list is known and the finding is outside an archive, and
"a suppression cicd could not identify" otherwise. A shadow that could not run
fails the row — the findings reported are real, but a pass cicd cannot read the
basis of is not one it can stand behind.

Traps: a suppressed tree result must not
stand for its location in `mergeGitleaksSARIF`, or it hides the history leg's
counted result at the same place; and the history leg is **not** shadowed, so
a suppression there stays undisclosed. Disclose, not refuse, for the same blast
radius as `.trivyignore`. See
[specs/disclose-gitleaks-suppressions.md](../../specs/disclose-gitleaks-suppressions.md).
