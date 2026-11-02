# Intent: prove the release merge was gated, instead of asserting it

## Why

`scripts/ci/deliver-release-pins.sh` writes this sentence into every release pull
request it opens:

> Auto-merge is armed. Once `ci` passes and this merges, the release run that
> follows finds the pins already at the target and cuts the tag.

Nothing verified either half of it. On 2026-08-04 both halves stopped being true
at once.

**Half one: `ci` stopped being required.** That evening the org
required-CI ruleset lost its only rule — `required_status_checks`,
context `ci`, `strict_required_status_checks_policy: true`, removed by an
org-level change; the ruleset itself survived, empty, so every UI that lists rulesets still
showed it attached to `main`. `GET /repos/context-and-oss/cicd/rules/branches/main`
afterwards returned three rules, all from the branch-protection ruleset, none of them a
status check:

```json
[
  {"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
  {"type": "non_fast_forward"},
  {"type": "deletion"}
]
```

A `pull_request` rule with zero required approvals reads like protection and
answers a different question. Nothing required any check to pass.

(Amendment for the public repository: its review ruleset requires one approval,
and rulesets match the *target* branch, so a release pull request is held by it
too. The release identity is a bypass actor on that ruleset, and the `--branch`
preflight now reads `pull_request` rules as well and refuses to deliver unless
the identity it runs as can bypass every ruleset that asks for a review — an
armed auto-merge nobody can fire is otherwise discovered by `release-drift`,
two days late. It asks by `GET /repos/{owner}/{repo}/rulesets/{id}` and reads
`current_user_can_bypass`: the org endpoint's `bypass_actors` list needs
administration *write* on the organisation, which no release credential should
hold, and no endpoint at all serves an enterprise ruleset to a repository
credential. The repository endpoint answers for every level with metadata read.)

**Half two: auto-merge was never armed.** `gh pr merge --auto --merge` cannot arm
auto-merge on a request that is *already* mergeable — with no required check,
every release pull request was mergeable the instant it opened, so the command
merged it on the spot. It exits 0 either way and reports which of the two
happened nowhere. Four consecutive releases went out that way, measured from
GitHub's API:

| PR | created | merged | Δ | auto-merge | `ci` started | `ci` concluded |
|---|---|---|---|---|---|---|
| 1 | 21:27:45Z | 21:27:50Z | 5s | `null` | 21:43:33Z | success 21:43:37Z |
| 2 | 06:06:59Z | 06:07:04Z | 5s | `null` | 06:21:48Z | success 06:21:51Z |
| 3 | 13:07:08Z | 13:07:13Z | 5s | `null` | 13:21:09Z | success 13:21:14Z |
| 4 | 13:09:21Z | 13:09:26Z | 5s | `null` | 13:22:59Z | success 13:23:04Z |

Five seconds from opening to merge; `ci` starting thirteen to sixteen minutes
*after* the commit was already on `main`, and passing.

That last column is why this is worth a module rather than a shrug. The two facts
a human — or a script — would use to tell a gated merge from an ungated one are
*the check exists* and *the check is green*. Both are true of all four commits,
permanently, and both are meaningless. **A gate that was never consulted is
indistinguishable, after the fact, from a gate that passed**, unless you compare
timestamps. This is the repository's founding doctrine — "a tool that could not
run must never read as clean" — reproduced inside its own release path, two
levels up from the scanners it was written for.

Nothing else here could have caught it. `release-drift.yml` watches whether
releases *stop*; these releases all succeeded. `ci` itself ran and passed on every
one of those commits; it simply ran too late to matter. The pull request body
asserted the gate, which is exactly the kind of claim this repository does not
accept from a scanner.

## What changed

`scripts/release_gate.py` — two pure functions over parsed JSON, no `gh`, no
subprocess, no clock:

- `read_gate(rules)` reads a `GET /repos/{owner}/{repo}/rules/branches/{branch}`
  body and reports whether a `required_status_checks` rule names the context,
  whether the strict policy is on, and which contexts *are* required. The
  endpoint returns *effective* rules flattened across Enterprise, org and repo
  rulesets, which is the right question: which level carries the check is not the
  pipeline's business.
- `merge_was_gated(doc, merged_at)` reads a
  `GET /repos/{owner}/{repo}/commits/{sha}/check-runs` body and asks whether the
  context concluded success *before* the commit merged. The latest completed run
  before the merge decides, matching GitHub's own semantics, so an earlier run
  cancelled by a concurrency group does not condemn a commit whose re-run passed.

`scripts/check-release-gate.py` fetches, prints and exits — `0` the claim holds,
`1` the claim is false, `2` the question could not be put to GitHub at all.

`scripts/ci/deliver-release-pins.sh` calls it twice:

- `--branch main`, as a preflight next to the existing credential preflight,
  before anything is written.
- `--delivered-pr N`, immediately after `gh pr merge --auto --merge`, asserting
  exactly one of *open with `autoMergeRequest != null`* or *merged with the
  context already concluded success on the head commit before `mergedAt`*.

## Proof

Both fixtures in the tests take the shape of real API responses, not invented
ones: the ungated three-rule body above, and the removed rule as the rules
endpoint reported it before the removal. Ruleset ids are fixture values.

- `scripts/tests/test_release_gate.py` — 33 tests. The first PR's real timings are
  refused; a check completed before the merge is accepted; completing in the same
  second as the merge is accepted (a merge triggered *by* the check can share its
  timestamp); a `pull_request` rule is not read as a gate; a differently named
  required context does not stand in for `ci`; a rule at any ruleset level counts;
  an unreadable body raises rather than returning "ungated".
- `scripts/tests/test_deliver_release_pins.py` — the same logic driven through the
  real delivery script with a stubbed `gh`: an ungated `main` stops the release
  before any push, the error names the ruleset and the rule to restore, the
  tagging and superseded paths are gated too, a `gh` failure is not a pass, and
  the readback runs after the merge command and before the supersede cleanup.

Ordering is tested with offset timestamps chosen so that a string comparison gets
it wrong in both directions: `23:20:00+02:00` is 21:20Z, before the merge, yet
sorts after it as text; `21:00:00-02:00` is 23:00Z, after the merge, yet sorts
before it.

## Decisions

**The preflight is what makes this durable; the readback alone is not.** If the
readback fails after the merge has already landed, the pins are on `main` — and
the *next* CD run finds them already at the target, takes the `released` path,
and cuts a tag without ever reaching a readback. So the branch check runs at the
top, on every path, including the one that only tags. A tag cut from an ungated
`main` is the same false pass one step further along.

**No override flag.** An escape hatch here is precisely how the claim rots again,
quietly. Restoring the rule is an org-settings action; a release blocked until
someone takes it is the correct amount of friction. The cost is real and stated:
with the ruleset as it currently stands, no release can be delivered at all.

**Exit 2 is a third answer, not a pass.** If the release credential cannot read
branch rules or check runs, the script fails before anything is pushed with a
message naming the endpoint and the permission. "Could not look" reading as
"looks fine" is the failure this whole change exists to remove; it would be
absurd to reintroduce it in the checker.

**A missing strict policy warns rather than fails.** Without it a stale, superseded
release branch could still merge later and walk every pin backwards — but the
supersede cleanup in the delivery script already closes those, so the warning
says that the cleanup is now the only thing defending it.

## Known residue

The release credential's ability to read `/rules/branches/main` and
`/commits/{sha}/check-runs` has only been probed with a maintainer's own `gh`
token, not with `CICD_RELEASE_TOKEN`. A fine-grained PAT missing repository
metadata read would produce exit 2 on the first release after this lands — loud,
before any push, with the endpoint named, and no half-written state.

This change proves the merge was gated. It does not prove the *gate* was
meaningful: `ci` concluding success on the head commit before the merge is what
gets asserted, and whether `ci` covers the right jobs remains the job of the
aggregate `ci` job's `needs:` list.
