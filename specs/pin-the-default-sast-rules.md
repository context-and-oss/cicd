# Pin the default SAST rules

## Why

The same commit of a consumer repository, scanned by the same pinned Semgrep
image with the same `--sast-rulesets p/security-audit`, applied **725** rules
on 2026-10-21 and **225** three days later. Both reports said zero findings
over the same file count. Nothing in the evidence could tell them apart, and
nothing in cicd had changed: `p/security-audit` is a registry name, resolved
by `semgrep.dev` at scan time, and the registry decides what it means.

That is the founding doctrine one field over. `Examined` made "zero findings
over how much?" answerable; nothing answered "zero findings *with what*?". A
rule set that lost two thirds of its rules overnight reads exactly like a
codebase that got cleaner, and every consumer on defaults was on it.

## What changed

**The default pack is pinned to a git commit.**
`p/security-audit` is no longer fetched from the registry. It is read from
`https://github.com/semgrep/semgrep-rules` at
`16b9e6d45f10649f6a531ec4838ed9924372c3bc` (`semgreppack.go`), fetched by
Dagger with the `.git` directory discarded. Which files and rule ids make up
the pack is frozen in `src/security/rules/semgrep-security-audit.txt`: 724
rows of `<path> <id>`, captured from the registry's 725-rule answer of
2026-10-21. The 725th is the upstream `gha-curl-pipe-shell`, left out because
its embedded-Bash parser still rejects valid run blocks. A runtime adapter
(`src/security/semgrep_gha.py`) reads that rule from the same pinned checkout
and replaces its Bash matcher with a parser-safe regex, retaining upstream
structure and notices rather than bundling them. At pinning time this applied
725 rules: 724 pinned plus the adapted workflow check. The later inline-JS
support also adds the first-party DOM rule.

`p/owasp-top-ten` and `p/secrets` are pinned the same way, at the same
commit (below, "The other two packs"). Any other registry entry
(`p/python`, `r/<rule>`) is still fetched live, and the evidence says so
(below). A path is a config in the consumer's own repository, versioned
with the commit being scanned, and is neither pinned nor reported unpinned.

**The rules a scan applied are recorded.** The semgrep row of
`sources[]` gains `rules` (`RuleSet` in `src/internal/evidence/schema.go`):

```json
"rules": {
  "count": 725,
  "byLanguage": {"python": 200, "javascript": 75, "cicd": 1, ...},
  "pinned": "p/security-audit, p/owasp-top-ten = https://github.com/semgrep/semgrep-rules@16b9e6d4…",
  "unpinned": ["p/python"]
}
```

`count` and `byLanguage` come from the SARIF's
`runs[].tool.driver.rules[]`, Semgrep's own list of what it loaded — not from
the manifest. `byLanguage` keys on the language directory the rule id names
(`cicd` for configs under cicd's rule directory, `other` for an id with no such directory,
which is what a consumer's own config produces).

**A pinned set below its floor is a non-run.** When a pinned pack is
selected, every id its manifest lists (724 for `p/security-audit`; the union
when several are named) must appear in the loaded rule list, compared case-insensitively. A missing id fails the row with
`ran=false` and an `errors[]` entry naming how many loaded, which pin, and the
first five ids missing. `--fail-on NONE` does not forgive it, because it is
not a finding: the scan that ran is not the scan that was asked for. A scan
that loaded **no** rules is a non-run whether pinned or not. Rules beyond the
manifest are not checked: they come from other configs and cannot be
attributed.

A live registry pack adds one `warnings[]` line, `semgrep: UNPINNED RULES —
<packs> fetched live from the Semgrep registry at scan time; …`, so a pass
that depended on the registry's answer that day says it did.

## The other two packs

`p/owasp-top-ten` (`rules/semgrep-owasp-top-ten.txt`, 559 rows, 551 files)
and `p/secrets` (`rules/semgrep-secrets.txt`, 52 rows, 52 files) were
captured from the registry on 2026-10-24 and mapped to files at the same
commit. Measured that day:

- Every file either manifest names is also in the `p/security-audit`
  manifest, whose files load exactly its 724 ids. So every rule a staged
  file brings is known, and a unit test
  (`TestSemgrepPackCeilingHoldsByConstruction`) keeps that true across a
  bump.
- `p/owasp-top-ten`'s 560 ids are all in `p/security-audit` except the
  upstream `gha-curl-pipe-shell`, which the runtime-adapted rule replaces as it
  does for the default pack.
- Its files carry three rules the pack does not include:
  `python.lang.security.deserialization.pickle.avoid-cPickle`, `avoid-dill`
  and `avoid-pickle`. An owasp-only scan passes them as `--exclude-rule`
  (in semgrep's own spelling), so it applies the pack, not the files.
- `p/secrets` never carried `gha-curl-pipe-shell`, so a secrets-only scan
  does not gain cicd's replacement. Its files carry no other rule.
- 17 rules are in both `p/owasp-top-ten` and `p/secrets`. Naming several
  pinned packs stages their files once, in table order, with one floor that
  is the union of their ids.

Exclusions are dropped whenever a live registry config is in the same scan.
`--exclude-rule` removes an id from every config, so excluding `avoid-pickle`
for a pinned `p/owasp-top-ten` would also silently remove it from a live
`p/python` that asked for it. The scan then loads the three pickle rules
too: more than the pinned pack names, which `rules.count` shows, rather than
less than the live pack asked for. A consumer config path does not drop the
exclusions: semgrep names its rules from their path in the consumer's tree,
so one of them shares an excluded id only if it sits at
`python/lang/security/deserialization/pickle.*` and reuses the rule id.

These two manifests are the registry's answer on 2026-10-24, not on
2026-10-21 when `p/security-audit` was captured. Nothing records what the
registry served for them before that day, so the pin fixes their membership
from now on and cannot prove it matches any earlier scan.

## How the pin reproduces registry ids

Semgrep derives a local rule's id from its path relative to the working
directory: the directory components, then the file's stem, then the rule's
own `id`. The registry's ids have the same shape with the language directory
at the root, e.g.
`python.django.security.injection.sql.sql-injection-using-db-cursor-execute.…`.
A config passed as `/src/rules/python/...` would produce
`src.rules.python...`, and the floor would compare against nothing.

So each manifest file `<dir>/<file>` is staged at `/<dir>/<stem>/<file>` in
the scan container, Semgrep runs with cwd `/src` and one `--config /<top>`
per top-level directory (23 of them). Measured against the registry's SARIF
for the same commit, this reproduces every id, with six differing only in
case (semgrep lowercases the path part, the registry kept the rule's own
`X509-…` spelling). Hence the case-insensitive comparison.

Staging into `/` means a top directory could collide with the image's own
filesystem. `parseSemgrepPack` refuses a manifest naming a reserved root
(`usr`, `src`, `tmp`, …), and the scan script refuses at run time if a
`/<top>` already exists in the image: a pack it could not stage cleanly does
not scan, and the row reads "could not stage the pinned rule set".

The pinned tree is fetched once per pinned scan through `dag.Git`. A live-only
scan fetches it lazily only if the measured workflow rule needs a compatibility
rerun; custom/secrets-only scans do not generate an unrequested replacement.
The adapted workflow check must appear among loaded rule IDs, including in a
live-only rerun. Source/notice/adapter failures are non-runs, not permission to
skip that check. See [runtime adaptation](adapt-the-workflow-rule-at-runtime.md).
A fetch failure is
a non-run naming the repository and commit, never a fallback to the
registry.

## Trade-offs taken

- **Intercept the name, rather than add a new one.** Consumers keep writing
  `p/security-audit`, and every consumer on defaults is moved to the pin with
  no workflow change. The cost: the name no longer means what `semgrep.dev`
  says it means today. That is the point, and the evidence's `pinned` field
  says which meaning applied.
- **One deliberate change for every consumer.** Anyone who scanned after the
  registry shrank sees roughly three times as many rules on the next run, and
  may see findings that were always there. This is a behaviour change and is
  recorded in `CHANGELOG.md`.
- **Egress moves.** The default scan now fetches from `github.com` instead of
  `semgrep.dev`. A runner that allows only the registry has to allow GitHub.
- **No Renovate.** A bump changes the rules, so the manifest has to be re-cut
  and the change reviewed as a rule-set change. A bot PR moving the sha alone
  would either fail the floor or, worse, pass with a membership nobody read.

## Bumping the pin

1. Pick the new semgrep-rules commit, and clone it.
2. Decide membership. The registry pack is defined server-side, not in the
   repository, so the list of ids is a decision: either keep the current ids
   and map them to files at the new commit, or capture the registry's answer
   (`semgrep scan --metrics=off --config p/security-audit --sarif-output …`
   on any tree, then read `runs[].tool.driver.rules[].id`) and diff it against
   the manifest before accepting it. Write any id that disappeared, or appeared,
   in the commit message.
3. Regenerate the rows: for each id, the rule file at the new commit whose
   `<dir dots>.<stem>.` prefix and rule `id` produce it. Exclude
   `*.test.yaml` and the upstream `gha-curl-pipe-shell` while it still fails
   to parse.
4. Do steps 2-3 for each pinned pack (`semgrepPinnedPackDefs`). Update
   `semgrepRulesCommit`, each manifest header,
   `TestSemgrepPackManifestIsTheFrozenSet`, and the excluded co-located rules
   in `TestSemgrepPlanAppliesThePackNotTheFiles`.
   `TestSemgrepPackCeilingHoldsByConstruction` fails if a pack's file is no
   longer in the `p/security-audit` manifest: then its other rules are
   unknown, and the plan cannot exclude them.
5. Prove it: `bash scripts/test-module-units.sh`, then a real scan
   (`dagger -m ./src/security call scan-source --src ./testdata/go-app …`)
   whose `rules.count` is the manifest's rows plus one. A manifest that names
   a rule the new commit does not produce fails that scan as below the floor,
   so a wrong bump cannot ship as a smaller clean result.

## Still open

- Every other registry pack (`p/python`, `p/typescript`, `r/<rule>`) remains
  live. It is reported as unpinned, not refused, because a consumer who named
  it asked for the registry.
- No script regenerates the manifests; step 3 above was done by hand against
  each capture. The floor makes a wrong regeneration fail loudly, not
  silently.
- Whether `--exclude-rule` matches an id case-insensitively is unmeasured;
  the plan passes semgrep's own spelling, which is the one that works.
- The floor checks membership, not content: a pinned rule whose pattern was
  edited upstream is a different rule under the same id. The commit pin is
  what fixes content; the floor only proves the pin was what loaded.
