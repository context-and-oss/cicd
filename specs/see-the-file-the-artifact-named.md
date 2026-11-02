# See the file the artifact named

`refs-infer-coupling`
reported *"artifact mentions specific files but none match the changed files in
this diff — artifact may describe a different change"* about artifacts describing
exactly that change.

## The mechanism

`checkRefsCoupling` couples an artifact to a diff by tokenising the artifact text
with `pathToken` and looking each token up against the changed paths. So it can
only ever couple on a name `pathToken` recognised. Anything the pattern is blind
to is not merely unmatched — it is invisible, and the artifact is judged as if the
author had never mentioned it.

The bare-filename alternation required a stem of at least three characters. That
minimum is load-bearing: it keeps the pattern from matching bare extension words
("go", "md", "ts") in ordinary prose. But `ci` and `cd` are two-character stems,
so `ci.yml` and `cd.yml` — the two most frequently changed workflow filenames in
this repository — could not be matched.

The failure then needs one more ingredient, which is the ingredient a good
artifact always has: a reference to a file it deliberately did **not** change. A
call site it explains, a module it left alone, a rejected option. With those,
`mentioned` is non-empty, so the early return does not fire, and nothing in
`mentioned` is in the diff.

Measured against the real rule code on the real pull request:

```
### PRE-FIX CAPS-012-composite-smoke-assert-passed.capsule.yaml
error    refs-infer-coupling: artifact mentions specific files but none match …
         excerpt: mentioned: comment.md, src/security/, src/cross-cutting/evidence/main.go
                | changed: .capsules/CAPS-012-…yaml, .github/workflows/ci.yml
```

That capsule's `intent` block contained *"The two sibling passed sites in ci.yml
gain a comment naming which strength each is"*. It named the changed file in
prose and still tripped.

## Why the direction of the failure still matters

This is a false **failure**, not a false pass, so it does not breach the founding
doctrine — which is why this was filed as a bug and not as urgent. It has two
real costs anyway.

The message was **actively misleading**. *"artifact may describe a different
change"* is the opposite of the truth here, and the reviewer's next move is to
re-read a correct capsule hunting an error that is not in it.

And it **taught authors to stop naming files.** The cheapest way to silence the
rule is to delete the mentions of *unchanged* files — the rejected options, the
call sites left alone, the modules deliberately untouched. Those are the most
valuable sentences in an artifact, and the rule priced them at one CI failure
each. A gate that pushes authors toward vaguer artifacts is working against the
`min-length` and `min-causal-language` rules sitting beside it.

## The fix, in two halves

**One — `yaml`/`yml` get their own alternation with a two-character minimum
stem.** The minimum stays three everywhere else, because "go", "md" and "ts" are
English-adjacent tokens while nobody writes `ci.yml` meaning anything other than
that file. It is not lowered to one: nothing here is named `a.yml`, and a shorter
stem buys no real filename.

**Two — the question is asked the other way round before the rule reports.**
`changedNameMentioned` scans the artifact text for each changed path, and for its
bare basename, as a literal token. This is the structural half, and it is the
reason the fix is not a wider extension list: `pathToken` is blind to every
extensionless name (`Makefile`, `Dockerfile`), every extension absent from its
list (`cliff.toml`), and every dotfile (`.nvmrc`). Widening the list fixes one
filename at a time, forever, and each of those would have been the next issue.

A verbatim occurrence of a changed file's name **is** coupling under any reading,
so this half can only remove findings, never add one.

Its boundary rules are asymmetric, and each side is a measured collision rather
than a symmetry:

- A preceding letter, digit or underscore disqualifies the match, because
  `domain.gov` contains `main.go` and coupling on that would suppress a finding
  the rule got right.
- A preceding `/`, `.` or `-` is fine: `src/quality/include.go` and
  `vite.config.tsx` are mentions of `include.go` and `config.tsx`, which is the
  same relation the existing suffix match already accepts.
- A following letter, digit, underscore, `-` or `/` disqualifies it, for the
  mirror-image reason (`include.golden`).
- A following `.` is deliberately allowed, because a filename at the end of a
  sentence is followed by a full stop far more often than by another extension.

A bare basename shorter than four characters is not searched at all, since a root
file literally named `ci` would otherwise couple to the word "ci" in prose. Paths
carrying a directory separator are searched at any length — they cannot collide
with prose.

## Why the severity stays `error`

The issue's option 4 was to soften `refs-infer-coupling` to `warn` whenever the
artifact's mentions resolve to real files in the tree, reserving `error` for
mentions that resolve nowhere. Rejected. After the reverse check, a remaining
error means the artifact named paths, none of them is in this diff, **and** none
of this diff's names appears anywhere in the artifact — which is precisely the
"describes a different change" signal the rule exists for. Softening it there
costs real bite for no remaining false failure. Option 4 would also need the rule
to read the source tree, which is a new Dagger call and a new failure mode inside
a gate, in service of a weaker discriminator: an artifact copy-pasted from
another pull request in the same repository mentions real files too.

## The message now says what it established

> artifact mentions specific files, but none of them is in this diff and no
> changed filename appears in the artifact — name a file this change touches, or
> the artifact may describe a different change

Both directions, and the action that closes it.

## What was proven

`src/cross-cutting/intent/rules_test.go` gains 40 subtests across four functions,
and the existing `TestPathTokenNoCollision`, `TestPathTokenMultiDotStems` and
`TestCheckRefsCoupling` suites still pass unchanged — including the extension-prefix
regression that exists because a previous pattern change truncated
`package.json` to `package.js`.

Both halves were negative-controlled by breaking them in place:

- Restoring the two-character minimum to three fails the four `ci.yml`/`cd.yml`
  token cases and nothing else.
- Short-circuiting `changedNameMentioned` to never couple fails exactly the
  `Makefile`, `cliff.toml` and `.nvmrc` cases — proving the pattern half does not
  cover them and the reverse check is load-bearing.

The measured CAPS-012 reproduction is pinned as a test case verbatim, and the two
positive controls (an artifact that names only unchanged paths; an artifact whose
only near-match is the `domain.gov`/`main.go` coincidence) confirm the rule can
still fire.
