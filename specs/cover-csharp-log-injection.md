# Cover C# log injection

## Why

A consumer replacing a hosted code-scanning product with cicd ran both on a
.NET consumer and compared the results. Two C# finding classes had no
counterpart in cicd at all:

- **Log forging (CWE-117).** Request input written to a log entry unencoded:
  a value with a line break forges a second entry in a plain-text sink.
- **Sensitive information in a log (CWE-532).** A credential written to a log.

No rule in the pinned `p/security-audit` or `p/owasp-top-ten` packs models
either flow for C#, and none of the pinned C# rules is marked interfile, so
neither `ScanSource` nor `ScanTaint` could report them. The Roslyn leg's
analyzers do not cover them either. A finding class that no leg runs reads,
in the evidence, exactly like a tree that has none.

## What changed

- **Two first-party Opengrep taint rules**, `rules/csharp-log-forging.yml` and
  `rules/csharp-secret-in-log.yml`, written for cicd under its own licence. No
  upstream rule body is copied.
  - *Log forging*: sources are `[From*]` parameters of a type that can carry
    text, public `string` parameters of a `*Controller` class, and
    `Request.*`; sinks are `ILogger.Log*`/`BeginScope` and `Console.Write*`.
  - *Secret in log*: the source is an identifier or member path whose last
    segment names a credential (`Password`, `ApiKey`, `ConnectionString`,
    `AccountKey`, …), with flags, policy values and names *about* a credential
    (`PasswordLength`, `HasApiKey`, `ConnectionStringName`) excluded. Sinks are
    the same. What a function returns from a credential is assumed safe.
- **One list of first-party rules.** `semgrepfirstparty.go` holds the DOM rule
  and the two C# rules: file, id, the id the engine loads it under, and
  whether it is interfile. The audit and OWASP defaults carry all three;
  `ScanTaint` carries the two interfile ones beside its upstream manifest.
- **Each rule is required where it is added.** A plan that adds a first-party
  rule requires its loaded id, as it requires the pinned floor; a rule that
  did not load is a non-run that names it.
- **Measured, not gated.** Both rules are WARNING, which cicd counts as
  MEDIUM, under the default `--fail-on HIGH`. A consumer who wants them to
  fail a build sets `--fail-on MEDIUM`.

## Measured

On the same .NET consumer, against the hosted product's results for the two
classes. Pinned Opengrep 2.0.0; the hosted product's locations matched within
three lines.

| Class | Hosted product | `ScanSource` (one function) | `ScanTaint` (default depth 3) |
|---|---|---|---|
| Log forging | ~30 locations | ~40% of them, a handful more | ~55% of them, about as many more |
| Secret in a log | ~25 locations | none of them, one other | the same |

The log-forging locations neither mode reaches are flows through a lambda or
a cache, and members the name heuristic below clears. The extra interfile
findings are mostly false positives of the shapes named below (an enum, a
date reached through an aggregate, a consumer's own sanitizer); a few are
genuine flows through a logging wrapper the hosted product did not follow.
Both interfile runs stopped at depth 3 on some chains and said so.

The hosted product's results for sensitive information in logs were all false
positives on review: values named like credentials that were not (a count, a
setting name, a flag). The rule here excludes those shapes by name.

## What gets worse

- **The rules see names, not types.** A member named `…Id`, `…Count`,
  `…Date` or `…Time` ends a log-forging flow because it is assumed to be a
  parsed value; a `string OrderId` is missed. A credential not named as one is
  missed by the secret rule, and an unrelated value that is is reported.
- **An enum parameter is a source.** The rule cannot tell an enum from a
  class; a `[FromQuery] Status status` logged as-is is reported although it
  cannot carry a line break.
- **One `Replace("\n", …)` clears a flow** although `\r` survives it. A
  partial sanitizer is still a deliberate one; reporting it would push teams
  to suppress the rule.
- **A compiled `Regex` instance is not a sanitizer.** `re.Replace(s, "")` has
  the same shape as `string.Replace(old, new)`, so the rule cannot tell which
  removes a line break. Only the static `Regex.Replace(s, pattern, …)` with a
  literal pattern that names a line break, whitespace or a negated class
  counts. A consumer's compiled sanitizer needs a reviewed suppression.
- **Lambdas and cached delegates.** A flow through a lambda stored and called
  later, or through a cache, is not followed, in either mode.
- **Structured logging is not modelled.** A JSON formatter encodes the value
  and makes the forged line harmless; the rule cannot see the sink's
  configuration and reports it anyway.

## Checks

- `src/security/semgrepfirstparty_test.go`: every `rules/*.yml` is wired, its
  body embedded verbatim, one rule per file, `Interfile` agreeing with the
  rule's own option; the C# rules C#-only WARNING taint rules; the default
  plan carries every first-party rule and the taint plan the two C# ones,
  passed before the exclusions; dropping any one fails with its id.
- `scripts/smoke/interfile-taint.sh` over `testdata/interfile-taint/csharp`,
  on the real engine: `ScanSource` reports the two same-function findings and
  passes at the default gate; `ScanTaint` reports the cross-function and
  cross-file ones and only those; `.Length` and `ReplaceLineEndings` stay
  negatives.

## Residue

- Raising either rule to the default gate needs a measurement on more than
  one consumer.
- The sanitizer list is closed. A consumer's own encoder is cleared by a
  reviewed `nosemgrep`, never by its name.
