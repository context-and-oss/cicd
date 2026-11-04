# notify module

Domain module: posts pipeline results to Microsoft Teams (Adaptive Card), GitHub PR comments, and Azure DevOps PR comments.

## Entry functions

```go
// Post Teams Adaptive Card via incoming webhook, and report what happened.
func (m *Notify) Teams(
    ctx context.Context,
    webhookUrl *dagger.Secret,
    summary *dagger.File,    // combined-evidence.json from cross-cutting/evidence
    pipelineName string,
    runUrl string,           // optional: CI run URL shown in card
) (*dagger.File, error)      // evidence envelope: delivered, skipped, or lost

// Build Teams card JSON without posting (useful for testing card structure).
func (m *Notify) BuildCard(
    ctx context.Context,
    summary *dagger.File,
    pipelineName string,
) (*dagger.File, error)      // card.json

// Build GitHub PR comment markdown.
func (m *Notify) GithubBuildComment(
    ctx context.Context,
    summary *dagger.File,
    pipelineName string,
) (*dagger.File, error)      // comment.md

// Build Azure DevOps PR comment markdown.
func (m *Notify) AdoBuildComment(
    ctx context.Context,
    summary *dagger.File,
    pipelineName string,
) (*dagger.File, error)      // comment.md
```

## Run locally

```sh
(cd src/notify && dagger develop)   # once, from repository root

# preview Teams card without posting
dagger -m ./src/notify call build-card \
  --summary ./smoke-evidence-go/combined-evidence.json \
  --pipeline-name precommit \
  export --path /tmp/card.json

# preview GitHub comment
dagger -m ./src/notify call github-build-comment \
  --summary ./smoke-evidence-go/combined-evidence.json \
  --pipeline-name precommit \
  export --path /tmp/comment.md
```

## Key files

- `main.go` — module type + `parseEvidence` (`//go:build !unit_test`)
- `teams.go` / `github.go` / `ado.go` — the Dagger entry functions (`//go:build !unit_test`); each resolves its secret and hands off to the delivery seam
- `delivery.go` — **the outbound HTTP seam** every channel shares. Untagged, no Dagger import.
- `card.go` — Teams Adaptive Card model + builder
- `render.go` — markdown rendering (`buildMarkdown`, `PipelineMarker`, `codeSpan`)
- `locationrollup.go` — groups `findings[]` by location above the detail table, so a truncated comment still says *where*
- `delivery_test.go` — `TestDeliveryHTTP`: drives `delivery.go` against a local `httptest` server
- `codespan_test.go` — round-trips hostile content through the real renderer; carries `decodeCodeSpan`, a CommonMark §6.1 reader
- `schema.go` — verbatim copy of `src/internal/evidence/schema.go`

## Delivery seam

All three channels build their request and interpret their response in
`delivery.go`. `newDelivery(secrets...)` is the production constructor; tests
point the package-internal `githubAPI`/`adoAPI` fields at loopback. There is
deliberately **no** public input that can redirect a notification.

- **Bounded.** 30s client timeout (`deliveryTimeout`). `http.DefaultClient` has none, so a hung webhook would stall the pipeline behind a step that cannot fail it.
- **One attempt, no retry** (`noRetryPolicy`). Notifications are non-fatal, so a retry loop would buy nothing and risks duplicate cards.
- **A 2xx is not proof.** GitHub comment create/update and ADO thread create must return the documented `id`. ADO answers an unauthorised POST with **HTTP 203 and an HTML sign-in page** — a status-only check reports a comment it never posted.
- **Secrets cannot leak.** A Teams webhook URL *is* its credential (the token is in the path) and `net/http` puts the full URL into every transport error, so URLs are redacted to `scheme://host/<redacted>`. Every error is also passed through `scrubSecrets`, so an endpoint that echoes a token back cannot put it into the pipeline log or the evidence `errors[]`.
- **Comment paging is bounded** to `maxCommentPages`; an endpoint that keeps returning full pages cannot spin the marker search forever.

Run the protocol suite with no Dagger session:

```sh
(cd src/notify && go test -tags unit_test ./...)
```

## The rendering seam

Every string this module puts inside backticks arrives from outside it, so
**`codeSpan` is the only thing allowed to write one.** Do not format a backtick
with `fmt.Fprintf` — that is what the defect was.

- **A backtick in the value used to close the span.** After it, the rest of the
  value was markdown, inside a comment posted under cicd's name beside a
  pass/fail verdict — so the person being gated wrote part of the gate's report.
  A backtick is legal in a git refname (`git check-ref-format --branch` accepts
  one), and a branch name reaches two sinks on every run.
- **It fences, it does not strip.** CommonMark §6.1: a span may be delimited by
  any number of backticks and contain any *shorter* run. Stripping would edit a
  finding's `path:line`, and a reviewer who follows an edited path lands
  somewhere else — the unlocated-finding-that-looks-located lie, only harder to
  notice.
- **Pad both ends or neither.** The parser strips one space from each end only
  when the content *both* begins and ends with one, so a single-end pad survives
  into the output and a path acquires a leading space. `escapeCell` ends in
  `TrimSpace`, so `cellCode` trims **before** it pads; the other order deletes
  the pad silently, and only on the inputs the pad exists for.
- **The Commit and Branch rows had no escaping at all** — not even newline
  flattening. A pipe is a legal refname character, so `feat/a|b` opened a third
  table column, and a newline in a value cut the row mid-cell. Three defects,
  two lines.
- **The test asserts a round trip, not safety.** "Output looks safe" passes a
  version that strips, i.e. licenses the rejected option. `decodeCodeSpan`
  recovers the content by CommonMark's rules and requires it to equal the input
  byte for byte.
- **`card.go` is deliberately not fenced, and the reason is measured.** An
  Adaptive Cards `TextBlock` renders a markdown subset with no code spans and
  *with* links, so a backtick there fences nothing and an injected link would be
  the real question. It is not one: every field that card renders is produced by
  cicd or is a refname, and git rejects `[` in a refname, so no field can render
  a link. The residue is `_` rendering italic. Escaping it would be an untested
  claim about a parser no job here may contact.

See [specs/fence-the-span-a-branch-name-can-close.md](../../specs/fence-the-span-a-branch-name-can-close.md).

### The rollup answers "where", which the truncated table cannot

`writeFindingsDetail` shows `maxRenderedFindings` rows and a count of the rest.
That answers "how many" and never "where" — and in a DAST envelope the location
*is* the endpoint, which is the one thing a reviewer of a web scan wants.
`writeLocationRollup` groups `findings[]` at render time, so there is no second
list to drift out of agreement with the table beside it.

- **Grouped on the path, not `path:line`.** Three findings on three lines of one
  file are one file to open, and ZAP reports no line at all, so keeping the line
  would be a no-op for the case this exists for and a de-grouping for every
  other. `TestBuildMarkdownFindingsShowTheLine` was narrowed from the whole
  comment to the detail table for this: a row *there* stands for one finding, so
  a bare path there is a dropped line; the rollup carries a count column.
- **Ordered by count, ties broken by first appearance.** The envelope's order is
  most-severe-first, so first appearance carries severity into the tie-break for
  free; alphabetical is equally deterministic and throws that away.
- **Silent when it compresses nothing and the table is not truncated** — it
  would be the same rows with a `1` in every count column.
- **Unlocated findings are counted separately and never placed.** Attaching one
  to the nearest path is the rollup inventing the fact it exists to report.

Tool-agnostic on purpose: no tool-name branch, so on a SAST envelope it groups
by file. Hence "Location" in the heading rather than "Endpoint".

## Constraints

- `Teams()` is non-fatal: `passed` is `true` in all three delivery states. A webhook outage must never red a scan, or a team learns to stop passing the webhook — which is the defect this returns from the other side. `outcome` tells them apart (`CLEAN` delivered, `SKIPPED` not configured, `ERROR` attempted and lost) and `warnings[]` carries the sentence.
- A blank webhook is **not** a webhook, and neither is an unexpanded `$(NAME)` Azure DevOps macro (`teamsUnconfiguredReason`; `--include` had the same fault). Anything else is attempted: a malformed URL is a broken configuration, not an absent one, and reclassifying it would tell a team relying on the channel that they never set one up.
- The delivery record only reaches a human because the composite aggregates evidence a **second** time with notify's envelope appended. `cross-cutting/evidence` drops `genericReport`, so `warnings[]` is the one channel that survives into `combined-evidence.json` and the PR comment. That second `Wrap` is also what *performs* the POST — a function returning `*dagger.File` is lazy — so skipping it does not save an aggregation, it stops sending cards.
- The `summary` file must be `combined-evidence.json` produced by `cross-cutting/evidence`.
- Endpoints are compile-time constants (`githubAPIBase`, `adoAPIBase`). Do not add a Dagger input to override them.
