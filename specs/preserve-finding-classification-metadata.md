# Preserve finding classification metadata

## Goal

A security-sensitive audit pattern and a style preference can both have Semgrep
severity ERROR. Severity answers neither what kind of diagnostic it is nor how
confident the rule author is. Reports need those dimensions independently.

## Bounded change

Schema 1.7 adds optional finding concern, category, subcategories, confidence,
weakness IDs and classification source. Semgrep's same-run native JSON supplies
an allowlisted projection in `properties.cicdFindingMetadata` on each SARIF
result. Ordinary, custom, inline-JavaScript and compatibility-rerun scans use the
same mechanism. The aggregator preserves that projection in normalized findings.

Missing/unsupported/malformed metadata stays unknown. Rule identities are joined
exactly within one invocation; conflicting projections for an identity are
unknown. No names, message keywords, ERROR/WARNING or SARIF precision are used to
guess classification. Only category vocabulary, audit/vuln labels, HIGH/MEDIUM/LOW
confidence and valid CWE identifiers can leave the projection. Arbitrary rule
metadata, matched text and alleged confirmation status do not.

Concern describes the producing scan, not security relevance: a custom style
rule run through SAST can carry concern sast and category style. Classification
source scanner-metadata describes provenance, never independent verification.

## Invariants

- Findings, severity, counts, suppression and fail-on semantics stay unchanged.
- Optional enrichment failure retains the original scan report.
- Native JSON is not exported wholesale. Existing SARIF redaction still runs
  before publication and retains only the safe classification projection.
- Native producer fields survive aggregation. Classified duplicates deduplicate;
  distinct metadata has a deterministic final tiebreak without changing severity
  or module-priority ordering. Detail caps do not manufacture category totals.
- Existing evidence remains readable; absent new fields are omitted, not defaults.

## Evidence and checks

`testdata/semgrep-finding-metadata` contains first-party synthetic rules/source
and real Semgrep OSS 1.162.0 native JSON/SARIF, captured from the pinned image
without network. No upstream rule bodies are copied. The security rule is
security/audit/LOW confidence; the style rule is style/HIGH confidence; the third
has no metadata. All three are ERROR, and all three SARIF rules have precision
very-high. Fixture README records provenance and reproduction.

Security Go/Python tests cover projection, exact identity/conflicts, unknown and
malformed metadata, unchanged severities/gates, redaction and scanner wiring.
Evidence tests cover extraction, serialization, legacy input, deterministic
ordering and list-aware deduplication. Schema shape-history/JSON tests defend
the additive minor bump; the canonical module runner executes both packages.

Local Dagger source scanning and Wrap on the first-party fixture prove the
scanner -> individual SARIF evidence -> combined findings path. No security-only
workflow, report UI, review-state store or new scanner is part of this change.
