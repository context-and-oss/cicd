# Fence the span a branch name can close

`notify` renders the pipeline's verdict into a PR comment. Six of the strings in
that comment arrive from outside the module — a branch name, a commit SHA, a path
a scanner read off the tree, a warning assembled from paths a container's `find`
returned — and every one of them was wrapped in a markdown code span by
`fmt.Fprintf` with a bare `%s` between two literal backticks.

A backtick in the value closes the span. Everything after it is parsed as
markdown, inside a comment posted under cicd's name, next to a pass/fail verdict.
So the person being gated writes part of the gate's own report.

## The sinks

| site | value | escaping before |
|---|---|---|
| `render.go` Commit row | `env.Repo.CommitSHA` | **none** |
| `render.go` Branch row | `env.Repo.Branch` | **none** |
| `render.go` warning list | every `warnings[]` entry | **none** |
| `render.go` error list | every `errors[]` entry | **none** |
| `render.go` `cellCode` | finding `path:line` | `escapeCell` — pipes and newlines, not backticks |
| `card.go` Commit / Branch | SHA, branch | none; see the Teams section |

`escapeCell` flattened newlines and escaped pipes and then `cellCode` wrapped its
output in a backtick it had never inspected. The other four had no escaping at
all — not even the newline flattening.

## Three defects in the same two lines, all measured

The Commit and Branch rows never called `escapeCell`, so they carried every
failure mode a table cell has:

| input | rendered before | what a reader saw |
|---|---|---|
| branch `` feat/x`whoami` `` | ``` `feat/x`whoami`` ``` | span closes at the second backtick; the tail is markdown |
| branch `feat/a\|b` | `` \| **Branch** \| `feat/a\|b` \| `` — four unescaped pipes | a third column; every cell after it shifts |
| SHA `abc\ndef` | `` \| **Commit** \| `abc `` | **the row is cut mid-cell** and `def` becomes a paragraph |

The second and third are not hypotheticals about a hostile actor; they are what
happens to any value that contains those bytes.

## The vector is a branch name, and git allows it

`git check-ref-format --branch`, measured:

| char | refname | consequence in the comment |
|---|---|---|
| `` ` `` | **accepted** | closes the code span |
| `\|` | **accepted** | opens a table column |
| `<` `>` `&` | **accepted** | raw HTML, inert once inside a span |
| `_` `#` `!` `]` `(` `)` | **accepted** | emphasis, mostly inert mid-string |
| `[` | rejected | — |
| `*` `~` `^` `:` `?` space | rejected | — |

A backtick is legal in a refname and a branch name reaches both sinks on **every
run**, with no misconfiguration required. That `[` is rejected matters later.

## Severity, stated accurately

`templates/github-actions/precommit.yml` triggers on `pull_request`, not
`pull_request_target`, and `pull_request_target` appears nowhere in this
repository. On a fork `pull_request` the token is read-only and secrets are
withheld, so the comment post fails and the Teams webhook is absent. **Under the
configuration this repository ships, a fork drive-by does not reach the sink.**
It is not written up as one.

What is reachable today:

- **A same-repo branch PR** from a contributor with push-to-a-branch but not
  merge rights. Full token, the comment posts, and they choose both the branch
  name and the file names a scanner will report. A privilege boundary, crossed
  inside the artifact that states the verdict.
- **Any consumer on `pull_request_target`** — and note how a team gets there.
  They hit the read-only-token wall trying to make PR comments work on forks, and
  `pull_request_target` is the first remedy the search results offer. That
  second-order effect is the more useful half of this section.

## The fix does not strip

Removing a backtick from a path changes a finding's location, and this package
renders locations as a `path:line` code span precisely so a reviewer can jump to
one. A silently edited path lands them somewhere else. That is the same lie as an
unlocated finding that looks located — see
[give-a-finding-its-line.md](give-a-finding-its-line.md) — only harder to notice.

CommonMark's own rule is both faithful and safe (§6.1): a code span may be
delimited by any number of backticks and contain any *shorter* run. So `codeSpan`
fences with the longest internal run plus one, and the content can never
terminate it. `longestBacktickRun` counts bytes rather than runes because U+0060
is single-byte in UTF-8 and cannot occur inside a multi-byte sequence.

**The pad is load-bearing and it is both ends or neither.** CommonMark strips one
space from each end of a span's content, but only when it *both* begins and ends
with a space and is not all spaces. So a pad on one end survives into the output:

| content | pad | span content | renders |
|---|---|---|---|
| `` `x `` | front only | ``  `x `` | `` `x`` — with a leading space |
| `` `x `` | both | `` `x  `` | `` `x `` — exact |

A path rendered with a leading space is the quieter version of the mutation
stripping was rejected for. Content already flanked by spaces gets the pad for the
same reason, and all-space content gets none because the strip rule exempts it.

**Ordering trap.** `escapeCell` ends in `strings.TrimSpace`. `cellCode` trims
first and pads second; the other order removes the pad silently, and only on the
inputs the pad exists for — so it is invisible to any test that does not use a
space-edged or backtick-edged input. That is why the round-trip cases include
`` ` ``, `` `x ``, `` x` `` and `" x "` rather than only a backtick in the
middle of a string.

One helper, not five: `writeQuotedList` now renders the warning and error lists,
so they get the flattening they never had, and an empty entry is skipped rather
than rendered as ``` `` ``` — two backticks with nothing between them are a
literal pair, not a span.

## Teams needs no fix, and that is measured too

`card.go` renders a *subset* of markdown through an Adaptive Cards `TextBlock`.
Code spans are not in that subset, so the backticks there fence nothing —
`[text](url)` **is** in it, which makes an injected link rather than an escaped
span the question on that surface.

It is not the question. Every field the card renders is either produced by cicd
(pipeline name, status, counts, duration) or is a git refname, and per the table
above git rejects `[`. **No field on this card can be made to render a link.**

The residue is emphasis: `_` is a legal refname character, so a branch name
containing one may render italic. That is cosmetic, it carries no destination, and
the alternative is escaping written against a parser no test here may contact — no
CI job posts to Teams, by the outbound-protocols rule. Escaping added on that
basis would be an untested claim about someone else's renderer. Named and bounded
in the code rather than papered over, because a half-fix that reads as whole is
this repository's founding doctrine turned on its own remedy.

## Negative controls

Each reverted in place and measured:

| revert | result |
|---|---|
| `codeSpan` → `` "`" + s + "`" `` | 4 of 4 tests fail; 11 of 13 round-trip cases fail — the two survivors are the cases with no backtick |
| pad one end instead of both | round trip fails: `" x "` renders `` `  x ` `` and decodes to `" x"` |
| Commit/Branch rows → bare `%s` | Branch row carries 4 unescaped pipes; Commit row renders as `` \| **Commit** \| `abc `` — cut mid-cell |

The round-trip assertion is the point. `decodeCodeSpan` in the test file applies
CommonMark's rules — equal fences, no run inside that long, the both-ends strip —
and requires the recovered content to equal the input byte for byte. That proves
both halves at once: the content could not terminate the span, **and** the fix did
not quietly edit the content to make it fit. A test that only asserted the output
"looks safe" would pass a version that stripped.
