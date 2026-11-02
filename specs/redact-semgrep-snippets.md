# Redact the source text Semgrep copies into its report

## Why

Every gitleaks run passes `--redact`, because the evidence envelope is a build
artifact anyone with repository read access can download, and a secrets scan
must not copy the secret into it. Semgrep had no such rule, and it needed one
more than gitleaks did.

semgrep writes the matched source into each SARIF result:
`region.snippet.text` holds the whole matched line. The default
`p/security-audit` carries the `generic.secrets.*` rules, and those match
exactly the line holding a credential. Measured on semgrep 1.162.0 (the pinned image) against a
file holding an AWS access key: the key appeared verbatim in the envelope's
`sarifReport`, through SAST, while the secrets leg beside it kept it out.

No CI cell saw it. Semgrep's AWS rule refuses any match containing `example`,
`sample`, `test` or `fake`, and every credential under `testdata/` carries one
of those words, so the rule never fired on a fixture.

## What changed

`src/security/semgrepredact.go` rewrites every semgrep report in
`runSemgrepOnce`, before anything reads it, so neither scan pass, the counts,
the rule set nor the envelope ever holds the matched source. Three channels
carry it, measured over the pinned rule set:

- **snippets** — every `snippet` key at any depth inside a result is removed:
  the location, `contextRegion`, `relatedLocations`, `codeFlows`;
- **fixes** — removed. 87 of the 710 pinned rule files carry `fix:` or
  `fix-regex:`, whose replacement text is built from the matched source;
- **the result message** — replaced with the rule's declared message from
  `tool.driver.rules[].fullDescription`. semgrep interpolates metavariables
  into the result's message, and 82 pinned rule files do;
  `yaml.kubernetes.security.secrets-in-config-file` writes
  `Secrets ($VALUE) should not be stored…` with the secret in `$VALUE`. The
  declared message keeps the placeholder. Nested messages inside a result are
  removed for the same reason. A result whose rule is not in the catalogue gets
  a message naming the rule and saying the text was withheld.

Kept: `ruleId`, `uri`, lines, columns, `suppressions` (so `nosemgrep`
acceptances still are not counted), `fingerprints`, `properties`, the rule
catalogue (`semgrepRuleSet` reads it) and the invocation notifications
(`semgrepnotifications.go` reads them) — less the source they quote.

### The notifications quote source too

A fourth channel sits outside the results. A `Syntax error` notification in
`invocations[].toolExecutionNotifications` quotes what the parser rejected
between backticks, and the quote is not a token: measured on 1.162.0, a
JavaScript file whose line is `function f( { const k = "<value>" }` produced

    Syntax error at line b.js:1:
     `function f( { const k = "<value>" }` was unexpected

— the whole line, string literal included. Python quotes the literal; TS and
JSON quote a token; C# quotes `public class Foo(int x)`. `semgrepnotifications.go`
then repeated that text in the `PARTIAL SCAN` warning as the first parser
message, so the value reached `warnings[]` as well as `sarifReport`.

`withholdSemgrepNotificationSource` rewrites every notification, execution and
configuration both: `snippet` keys at any depth are removed, and in
`message.text` and `message.markdown` everything from the first backtick to
the last becomes `[source withheld]` — a lone backtick withholds to the end of
the text. Kept: the descriptor, the level, the path, the line and the rule id
(semgrep quotes rule ids with single quotes, so the GitHub Actions fallback in
`semgreprules.go` still recognises its notification). The warning now reads
`First parser message: b.js:1 [source withheld] was unexpected.`
`semgrepSyntaxLocation` applies the same rewrite to what it extracts, so the
warning holds even for a notification that reached it unredacted.

Greedy, not paired: source can hold backticks (template literals, `$(…)` in
shell), and a pairwise match would end the quote at the first inner backtick
and keep the rest. The cost is that prose between two quotes is withheld too.
A notification list the rewrite cannot walk is an error, as for results.

A report the rewrite cannot read is an error, not a pass-through: a document
cicd cannot parse is exactly the one whose text it cannot prove it withheld.
`semgrepRunError` has already accepted the report as SARIF by then, so this
fires only on a shape it does not expect.

## Trade-off

The result message loses its interpolation for those 82 rules: a reader sees
`$FUNC` where semgrep would have written the function name. The location is
kept, so the reader opens the line. A message that names a variable is not
worth one that can name a secret, and cicd cannot tell which metavariable binds
which.

## Residue

- The `fingerprints.matchBasedId/v1` value is a hash over the match. It is kept
  because it is how a finding is recognised across runs; a hash of a
  high-entropy credential does not recover it.
- Only backtick quotes are withheld, because they are the only quoting shape
  measured. A semgrep that quoted source another way in a notification would
  pass through; YAML's `Other syntax error` quotes none.
- A path that itself contains a backtick loses its name from the warning (the
  rewrite starts there); the file is still counted as unparsed.

## Proof

- `src/security/semgrepredact_test.go`: a report with the secret in every
  channel above comes out with zero copies; ruleId, location, fingerprint,
  suppression, catalogue and notifications survive; the severity counts are
  unchanged; an unreadable report is refused without quoting it. A report whose
  notifications quote a credential — a whole JS line, a template literal with
  inner backticks, a lone backtick — keeps no copy, while the unparsed file
  list, the timeout, the first parser message's path:line and the GitHub
  Actions fallback survive; notifications the rewrite cannot walk are refused.
- `scripts/smoke/semgrep-redaction.sh`, run by the security `module-test` cell
  and `make smoke`: a probe AWS key assembled at run time — so no
  credential-shaped string is committed — must be reported by semgrep (the
  positive control) and must appear nowhere in the serialised envelope.
