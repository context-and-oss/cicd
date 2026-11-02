# Compact the documents no one reads by eye

## Why

`Evidence.wrap` writes four JSON documents and until now indented all four,
because `json.MarshalIndent` was the first thing reached for and nothing later
questioned it.

Two of the four are read by a person. `combined-evidence.json` carries the
verdict; `parts/index.json` says what the run should have produced. Someone
chasing a finding opens both, and indenting them costs nothing at their size.

The other two are never read by an eye. `findings.sarif` goes to
`upload-sarif` or a SARIF viewer, `sbom.cdx.json` goes to an SBOM tool, and
every consumer in this repo reaches them through `jq`. Observed bundles spent
a substantial fraction of their bytes on indentation in those documents.

That is a disk argument, and on its own it would not be worth a change. The
reason it is worth one is the transfer cap. The engine refuses a single
transfer over 128 MiB, and the saving grows with the document. An observed
bundle failed to return because its indented `findings.sarif` exceeded that
cap; compacting the same document brought it below the cap. The original size
figures are omitted. Whether that run had evidence at all was decided by
indentation of a file no one would open.

A bundle that fails to transfer is this repo's own failure class: the run
scanned, the run found things, and the consumer saw nothing. It is worse than
a red verdict because it arrives shaped like an infrastructure hiccup.

## What changed

`marshalBundleDoc(name, v)` in `bundle.go` encodes a bundle file according to
who opens it, and `readByEye(name)` holds the list. `wrap.go` now routes all
four documents through it instead of calling `json.MarshalIndent` four times,
so the choice is stated once and in a file the tests can reach.

`readByEye` defaults an unknown name to indented. A document added later is
more likely to be a summary than a dump, and guessing wrong in that direction
wastes bytes instead of making a file unreadable.

## Proof

`TestMarshalBundleDocChangesNothingButWhitespace` decodes both forms of the
same value and requires `reflect.DeepEqual`, because the claim being made is
that no consumer sees a different document. `encoding/json` escapes `<`, `>`
and `&` identically either way, so the test value includes `a < b && c > d`.

`TestReadByEyeKeepsTheSummariesIndented` pins both directions, including a
path-qualified `audit/findings.sarif`, since the parts index is passed with its
directory attached.

`TestMarshalBundleDocNamesTheFileItCouldNotEncode` covers the error path the
rewrite moved: the four call sites each had their own `marshal X` message and
now share one, so the name has to come from the argument.

Mutating `readByEye` to return true for everything fails 3 of the 4 tests.

## What this does not do

It does not remove the cap, it moves the point at which a run hits it. A scan
with enough findings still overflows, and it still overflows with the same
opaque `134250496` error (the public 128-MiB reader limit plus one fixed
32-KiB chunk) that names neither the document nor the module. That
is a separate piece of work, and this change makes it rarer without making it
any easier to read when it happens.
