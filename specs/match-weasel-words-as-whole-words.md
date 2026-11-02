# Intent: the weasel-word rule must match whole words, not substrings

## Why

`checkNoWeaselWords` in `src/cross-cutting/intent/rules.go` was a bare
`strings.Contains` over a list of unmeasurable qualifiers. Any listed word buried
inside a longer word therefore produced a finding, and because the intent gate runs
at MEDIUM in this repository's own dogfood pipeline, such a finding blocks a merge.

It did. `specs/classify-a-refused-release-push.md` was rejected for
`robust, fast`, where:

- every one of the six `fast` hits was **`non-fast-forward`** — git's own rejection
  wording, and the exact string the classifier that spec describes greps for, so the
  spec cannot avoid the term; and
- the single `robust` hit was **`robustness`**, in a sentence arguing that a retry
  loop *claimed* more than it delivered.

A gate that refuses an artifact for quoting the tool it is about is not measuring
anything. Worse, the only ways to satisfy it were to stop naming git's error or to
disable the rule, and both cost more than the rule returns.

Two further artifacts already on `main` carried the same defect:
`docs/how-to-guides/run-pipeline-locally.md` for `simplest` and
`docs/how-to-guides/use-complete-pipeline.md` for `fastest`.

## What changed

`src/cross-cutting/intent/rules.go` now tokenises the prose before matching, since
the boundary cannot be expressed in the pattern:

- **`\b` is the wrong boundary.** A hyphen is a non-word character, so it *is* a word
  boundary and `\bfast\b` matches inside `non-fast-forward` exactly as the substring
  did. Go's RE2 has no lookbehind, so `(?<![\w-])` is unavailable.
- **Hyphens and underscores stay inside a token.** `non-fast-forward`, `fast-forward`
  and `fast_path` are each one word, and none of them is `fast`. Hyphenated list
  entries (`world-class`, `cutting-edge`, `state-of-the-art`) still match, because
  they are whole tokens too.
- **Punctuation becomes a barrier token, whitespace does not.** The list holds one
  multi-word entry, `best practice`, matched as adjacent tokens. Collapsing all
  separators to spaces would let it match across a sentence boundary in
  `the best. practice was poor`, so `weaselPunctuation` substitutes ` | ` and
  `weaselSpace` splits the result.

- **Quoted material is not the author's claim.** Writing this spec surfaced the same
  defect one layer up: naming an entry in order to explain it was itself a finding, so
  the rule could not be documented, and any artifact quoting a tool message that
  happens to contain a listed word was blocked. A fenced block or a code span is a
  quotation — a tool's output, a flag, an identifier — so `weaselFenced` and
  `weaselSpan` remove both before matching. This applies to this rule alone;
  `checkRefsCoupling` must keep code spans, because that is where artifacts name the
  paths it couples against.

`src/cross-cutting/intent/rules_test.go` gains `TestCheckNoWeaselWordsWholeToken`:
19 cases covering each regression (`non-fast-forward`, `fast-forward`, `robustness`,
`inflexible`, `simpler`, `oversimplified`, `fast_path`) alongside the matches that
must survive (standalone words, trailing punctuation, parentheses, markdown code
spans, sentence-initial and sentence-final position, case folding, hyphenated
entries, the multi-word entry, and several distinct words in one sentence). Each case
also asserts the message names *no* word absent from the text as a token, so a fix
cannot pass by reporting everything. `TestCheckNoWeaselWordsIgnoresQuotedMaterial`
adds 9 cases for the quoting half: spans and fenced blocks are exempt, prose beside
them still counts, an unclosed backtick does not swallow the rest of the artifact, and
a span between two words does not let them join into the multi-word entry.

## Proof

The rejected artifact, run through the same `extractText` the gate uses, with the
previous implementation reproduced verbatim beside the new one:

| Implementation | Verdict on `specs/classify-a-refused-release-push.md` |
| --- | --- |
| `strings.Contains` (before) | `[robust fast]` — matches the CI annotation that blocked the merge |
| whole-token (after) | no finding |

Blast radius, measured by running both implementations over all 42 markdown
artifacts under `specs/` and `docs/`: **two** verdicts change, both by dropping a
substring hit (`simplest`, `fastest`). No artifact gains a finding, which holds by
construction — the new matcher accepts a strict subset of what `strings.Contains`
accepted, so this change cannot fail an artifact that passes today.

`GOWORK=off go test -tags unit_test ./...` in `src/cross-cutting/intent` passes.

## Decisions

**Narrow the rule rather than shorten the list.** Dropping `fast` would have unblocked
the merge with one line, and it would have cost the rule its purpose on every artifact
that calls a change `fast` without a number beside it. The defect is the matcher, so
that is what changed.

**Inflections are now out of scope, deliberately.** `simplest`, `fastest`, `simpler`
and `well-optimized` no longer produce findings. They were only ever caught by
accident, as substrings, in the same mechanism that caught `non-fast-forward` — there
was no decision behind it. If those forms are worth gating, they belong in
`weaselWords` as explicit entries, which is a decision about what the rule measures
and needs its own change.

**Tokenise instead of pre-compiling one pattern per word.** A per-word regex would
still need the hyphen boundary that RE2 cannot express, so it would not fix the
blocking case at all.

## Known residue

**A weasel word inside a hyphenated compound is no longer reported.**
`well-optimized` and `easy-to-use` now pass. This is the direct cost of the boundary
that lets `non-fast-forward` through, and the trade goes this way because a rule that
blocks merges has to be wrong in the permissive direction: a missed qualifier is a
weaker artifact, whereas a false finding stops honest work and teaches people to
route around the gate.

**The two artifacts on `main` are left as they are.** `simplest` and `fastest` stop
being findings as a consequence of this change rather than as its aim, and rewording
them is an editorial change to unrelated documents.

**Only backticks mark a quotation.** A word in double quotes still counts as prose,
which is why this spec writes every entry it names in a code span. Markdown block
quotes and indented code blocks are not exempt either — `extractText` discards the
block structure that would identify them, so widening the exemption means teaching
extraction about structure first. A code span is the one quotation form available
without that.

**A listed word genuinely used inside a span escapes the rule.** Emphasis in backticks
is common enough that this is a real hole, and it is the cost of the exemption. It goes
this way because the alternative blocks honest work: before this change the rule could
not be documented at all.
