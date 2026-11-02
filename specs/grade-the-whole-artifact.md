# Grade the whole artifact

`refs-infer-coupling` reported *"artifact mentions specific files, but none of them
is in this diff and no changed filename appears in the artifact — name a file this
change touches, or the artifact may describe a different change"* about
a capsule, an artifact whose
prose names both files the change touched.

This is [see-the-file-the-artifact-named](see-the-file-the-artifact-named.md) one
layer earlier. That spec widened the rule so it could see a filename it was blind
to. Here the rule was given a document with the filenames removed.

## The mechanism

`extractYAMLText` in `src/cross-cutting/intent/extract.go` reduces an artifact to
the prose the rules grade. It decided line by line, and two of its branches
destroyed prose:

- A line holding a colon but no `": "` was dropped **entirely**. The only
  continuation branch was `if !strings.Contains(trimmed, ":")`, so a line the
  key/value branch had already declined was then declined again by the branch that
  existed to catch it.
- A line holding `": "` anywhere was **truncated** to whatever followed the first
  one, because the key/value branch matched prose as readily as a key.

Block-scalar bodies were never tracked, so a capsule's paragraphs — which is where
a capsule keeps everything worth reading — were fed through both branches.

Colons in this repository's prose are neither exotic nor avoidable: `//go:build`
has one, a URL has one, `[[:space:]]` has two, and any sentence reporting a
measurement has one. The behaviour required a capsule to be written around its own
extractor.

## Measured

Over the 24 capsules in `.capsules/`, before the fix:

| | bytes |
|---|---|
| raw | 195714 |
| never reached a rule | **29456 (15.1%)** |
| after the fix | 25220 (12.9%, keys and structure) |
| prose recovered | 4236 |

`CAPS-024` alone lost 1026 of 7875 bytes (13.0%). The line that mattered read:

```
it lives in dotnetreport.go which is untagged. test.go is //go:build !unit_test
```

`dotnetreport.go` and `test.go` are the two files the change edited. Both are
present in the raw file and absent from the extracted text. The only `pathToken`
match that survived named an unchanged consumer build-properties file, which
was cited precisely because it was **not** part of the change. That is the
ingredient a good artifact always has, and it is what turns the finding from
"mentions no files" into "mentions files, none of them yours".

Two capsules lost bytes rather than gaining them: `CAPS-010` by 6 and `CAPS-019`
by 8. That is correct, and the arithmetic is checked rather than assumed — a
folding indicator alone on a line used to be emitted as prose, because the
key/value branch read `>` as the value. `CAPS-010` recovered 8 bytes of prose and
stopped emitting 7 indicators worth 14 bytes.

## It failed in both directions

The captured failure is a false **red**, which does not breach "a tool that could
not run must never read as clean" and is therefore filed as an inconvenience
more readily than a false pass would be. It is not one, for the same reason the earlier spec gave: the
cheapest way to silence the finding is to delete the artifact's mentions of
*unchanged* files — the rejected options, the call sites left alone — which are
the most valuable sentences in a capsule. The rule works against the `min-length`
and `min-causal-language` rules beside it.

The other direction is a false **pass**, structural and uncaptured:
`checkNoTBD` and `checkNoWeaselWords` never saw a dropped line either, so a
placeholder or a weasel word sitting next to a colon was graded as absent. A gate
that reads part of a document and reports on all of it is this repository's
founding doctrine applied to prose.

That is why the fix is the extractor and not the rule. Widening
`checkRefsCoupling` a second time would have closed the red and left every other
rule grading a mutilated document.

## The fix

A block scalar is tracked by the indentation of the key that opened it, which is
YAML's own rule for where the body ends, so the extractor agrees with the parser
`check-capsules` already runs over the same file. A blank line inside the body is a
paragraph break, not a terminator — closing there would drop every paragraph after
the first, and that loss would look exactly like the loss being repaired.

`isBlockScalarHeader` stays exact, and the reason is the fix's own hazard: matching
a leading `>` loosely would read a line of prose beginning with a quotation marker
as a block header and swallow the paragraph beneath it — the same silent loss,
arriving through the repair. `opensBlockScalar` likewise refuses to read a line of
prose ending in a colon as a key.

## Negative control

Run with the new helpers left in place, so the control isolates the loop rather
than the compile. The shipped loop over the same fixture drops `dotnetreport.go`,
`test.go` and `//go:build !unit_test`, and fuses two sentences into one:

```
... It lives in nothing in it is reachable from the only suite that runs without
a Dagger session.
```

`Measured: 16 documents` became `16 documents`. The corruption reads as fluent
prose and is grammatical, which is why nothing caught it for twenty-four capsules.

## The audit that had to happen first

The fix can only *add* text to what the rules see, so it can only add findings, and
a gate that starts failing artifacts nobody edited is a worse outcome than the
defect. The four prose rules were run over all 24 capsules and 57 specs at both
revisions: **0 findings before, 0 findings after, over 81 artifacts.** The risk was
real and did not materialise.

## Not done

The artifact is not parsed with a YAML library. The gate reads capsules and
markdown specs with frontmatter, `extractMarkdownText` reuses this function for the
frontmatter half, and a real parser would reject a malformed document where the
gate's job is to grade whatever it was handed. What is fixed here is a line-based
extractor that lied about its own coverage — not the choice to be line-based.

Tests: `src/cross-cutting/intent/extract_test.go`. Capsule: `CAPS-025`.

## And this spec could not name the rule it fixes

Recorded because it is a permanent consequence of the fix, not a one-off. Once
the whole artifact is graded, an artifact **discussing** the placeholder rule
trips it. `tbdPattern` is case-insensitive and word-bounded over three
placeholder tokens plus a bare triple question mark, so the Go identifier
`checkNoTBD` does not match — `o` to `T` is no word boundary — while the rule's
own hyphenated name does, because a hyphen is a non-word character. The first
draft of this spec and of CAPS-025 both tripped it on exactly that, and the
dogfood job caught them. The pattern itself is not quoted here: writing it out
supplies boundaries on all three tokens and trips the rule three more times,
which was also measured.

Not fixed by widening the rule. No text rule can separate a prose mention of the
token from a real placeholder, so any exemption — quoted, backticked, inside a
code span — is a documented way to write a placeholder that never fires, which is
the shape this repository refuses everywhere else. The artifacts are reworded
instead: name the rule by what it does, not by the token it looks for.

The audit that preceded the commit ran the four prose rules over 24 capsules and
57 specs at both revisions and found nothing at either. It did not cover the two
artifacts being written alongside it, which is where the risk landed.
