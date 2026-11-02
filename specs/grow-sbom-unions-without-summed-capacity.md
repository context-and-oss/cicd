# Grow SBOM unions without summed capacity hints

## Why

CodeQL reported six allocation-size-overflow paths at three capacity hints in
`src/cross-cutting/evidence/cyclonedx.go`: the recursive object merge and the
array union's output slice and deduplication map. Each hint added two input
lengths, and each operand produced a report. These were capacity estimates,
not bounds required by the merge algorithm.

A production overflow was not reproduced. Existing input collections already
occupy memory and the evidence reader has a per-file limit, so a scanner path
is not proof that an attacker can reach the arithmetic boundary. Nevertheless,
the unchecked additions are unnecessary because Go can grow both collection
types while preserving every entry. Remove the arithmetic rather than suppress
the findings or claim six demonstrated exploits.

## Mechanism

`mergeCDXValue` initially sizes its new map from the first map's length.
`unionCDXArrays` initially sizes its output and seen set from the first array's
length. Adding the second input uses normal map insertion and slice append.
No code computes a combined allocation size, no fixed input limit is added,
and there is no new configuration or error path.

The merge contract is unchanged: objects merge recursively, conflicting
non-empty scalars still error, arrays deduplicate by canonical JSON and retain
first-seen order, and inputs are not modified. Empty array unions remain
non-nil empty arrays. Existing merge tests retain the conflict and identity
checks; `src/cross-cutting/evidence/cyclonedx_union_test.go` adds direct checks
for empty and one-sided inputs, growth from the second input, overlap,
canonical objects, scalar types, recursive union and input preservation.

## Rejected alternatives and traps

Checked addition would introduce a new branch merely to preserve an optional
estimate. Saturating the sum could request an allocation much larger than the
actual deduplicated result. Neither is needed to compute the union.

Do not restore a summed hint as a performance-only change without addressing
integer overflow. This hardening does not claim to prevent general resource
exhaustion from large documents, and ordinary-size tests cannot reproduce a
near-maximum-int collection without unrealistic memory requirements. Hosted
CodeQL analysis, rather than a successful unit suite, establishes whether the
original alerts close.
