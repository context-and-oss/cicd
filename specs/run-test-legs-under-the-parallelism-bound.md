# Run test legs under the parallelism bound

## Problem

`quality.Test` ran its declared legs one after another. A repository that
splits a slow suite into legs (unit, integration, one per service) paid the sum
of their wall clocks, even on a runner that could hold several. `--parallelism`
already existed, but it bounded only the check groups stage-2 overlaps, and
every description said so: "Does not change … test-runner concurrency".

The obvious alternative, letting consumers run their own shards and hand cicd
the reports, is rejected. A report cicd did not watch being produced is
co-authored by the thing it grades (the doctrine rule on co-authored reports).
Shards that cicd itself starts and witnesses are the honest form; they were
measured and are rejected too, for a different reason (below).

## Decision

- `quality.Test` takes `--parallelism` (1–4, default 1), validated by the same
  `ValidateParallelism` as stage-2, and runs its legs through `RunBounded`
  (`legschedule.go`). Default 1 is the old behaviour.
- stage-2 and the commit composite's app mode forward the same value. There is
  one knob, not two. A second `test-leg-parallelism` input would have had to be
  threaded through stage-2, two composites, three workflows, four ADO templates
  and a contract for a distinction nobody asked for.
- The bound applies at both levels, so the peak is **2p−1** containers (p legs
  in flight beside the other p−1 groups), not p². Every description site says
  so.
- Each slot writes its outcome by declaration index. The fold runs afterwards
  in declaration order, so the evidence is the same as a sequential run's
  except for the new per-leg `durationMs`.
- A leg the bound never started (the context was cancelled) is an error from
  `Test`, not an envelope row. A row means the leg ran or was refused for a
  reason it names; "never scheduled" is neither.

## What concurrency broke, measured

**Identical services were one service.** The engine dedupes identical service
definitions. Two legs each declaring `redis:7-alpine` as `cache` were given one
Redis: each leg ran `INCR hits` and required 1, and at `--parallelism 2` leg b
read 2 and the run was FAILED. Every service container now carries the label
`dev.cicd.test-leg-service=<leg>/<alias>` (`serviceInstanceKey`). The same probe
reads 1 in both legs and is CLEAN.

**Identical legs were one run.** Two legs with the same image and command were
executed once, and both rows reported the same `durationMs` to the millisecond.
That was already true when legs ran sequentially; the new duration field made it
visible. Each leg now sees its own label as `CICD_TEST_LEG`, and labels are
unique, so every row is a run.

**Shared package caches.** The leg containers mount the repository-scoped
package caches (`commandCaches`). See the NuGet section below.

## NuGet: two cold restores into one volume race

Two .NET legs (`sdk:8.0`, `testdata/dotnet-app`, distinct commands) at
`--parallelism 2`, each run under a fresh repository scope so the shared
`cicd-nuget-<scope>` volume starts empty: 3 runs in 4 failed both legs, with
`dotnet restore` reporting `Could not find file
'/root/.nuget/packages/system.runtime.handles/4.0.1/<random>.ucq'`. NuGet
extracts a package into a temp file beside its final folder and serialises
concurrent extractions with a lock under `/tmp/NuGetScratch`. That `/tmp` is
each container's own, so the two restores never saw each other's lock and one
renamed or deleted a temp file the other was still writing. The one passing run
had both legs report the same duration, which was the identical-legs dedup
above, not luck.

This was not opened by this change. stage-2 at `--parallelism` above 1 already
overlaps `quality.Check` and the witnessed `quality.Test`, both of which restore
into the same volume, and two pipelines on one persistent engine collide the
same way. Concurrent legs only made it routine.

The NuGet packages mount in `quality` (`commandCaches`) and `security`
(`dotnetexec.go`) is now `CacheSharingModePrivate`: a run that finds the volume
in use gets its own, so a concurrent restore starts cold instead of corrupting
the other one. Re-measured the same way, 4 runs in 4 were CLEAN, both legs
restored from the network side by side (15–27 s each) and the two rows reported
different durations.

- `CacheSharingModeLocked` is rejected: it holds the volume for the whole exec,
  so it serialises the entire .NET leg (restore, build and test), which is the
  sequential run `--parallelism` exists to avoid.
- A per-leg volume is rejected: it would make every leg cold on every run,
  where `PRIVATE` costs a cold cache only to a run that overlaps another.
- npm, pnpm, yarn and corepack stay shared. They lock or write atomically
  inside the store they share, and nothing here measured them racing; that is a
  claim from their design, not a measurement.

**Still open:** in a witnessed leg, a `dotnet restore` failure reads as "test
command failed" (FAILED), not as a non-run. That predates this change; the
combined verdict still goes red through `errors[]`, but `--fail-on NONE` on the
leg alone would pass it.

## In-engine shards, measured and rejected

Declared legs overlap work that is *different*: a Node suite beside a .NET
suite, unit beside integration. The question left open was whether cicd should
also split *one* suite into shards it starts and witnesses itself
(`vitest --shard i/n`, one leg per shard). In a measured consumer trial,
sequential and concurrent shard configurations on one Dagger engine were all
slower than a single leg. Shard totals matched the single-leg test count.
The precise timing matrix, runner capacity and suite inventory are omitted;
this is not a new benchmark or a claim about every suite.

The observed result is consistent with these limits for a CPU-bound suite:

- Vitest's worker pool already saturates the engine's CPUs from one leg, so a
  second leg on the same engine competes for the same cores instead of adding
  any.
- Each shard is its own container and repeats the dependency install. That
  overhead grows with the shard count without adding CPU capacity.
- The shards share one engine, so they cannot borrow a second machine's CPUs,
  which is the only thing sharding would buy.

All compared runs had the same test failure caused by an unavailable
checkout capability. That limits the evidence to a relative comparison of
those configurations, not a successful-suite throughput benchmark.

Cross-machine sharding adds CPU capacity; in-engine shards do not. A
cross-runner fan-out would have to merge evidence from engines cicd did not
witness together, and that is the co-authored report the alternative above was
rejected for. Neither form is planned. A consumer with one slow suite should
raise the runner's CPU count (`runs-on` a larger runner) before splitting it.

## Blast radius

- Nothing changes at the default. At p>1 a consumer's legs must not depend on
  running one after another: two legs writing the same external resource (a
  shared database the consumer hosts, a fixed temp path outside the leg) now
  race. Declared services are per leg and are not affected.
- `CICD_TEST_LEG` changes every leg container's definition once, so the first
  run after upgrading misses the engine cache for each leg.
- Peak runner load at p=4 is 7 containers.

## Verification

- `legschedule_test.go`: declaration order survives reverse completion, the
  bound is honoured (peak 2 at p=2), p=1 is sequential, a cancelled leg is the
  error `test-leg <label> did not start`, and `Duration` reaches `durationMs`.
- `byotestplan_test.go`: parallelism 0 and 5 are refused before any container,
  and four legs at p=4 are accepted.
- `services_test.go`: the instance key is distinct per leg and per alias.
- `src/quality/nugetcachesharing_test.go` and
  `src/security/nugetcachesharing_test.go`: every NuGet packages mount carries
  `CacheSharingModePrivate`, and a file with no such mount fails rather than
  passing vacuously. Changing the security mount back to `Shared` turns it red.
- End to end, the Redis probe above, with and without the label, and the NuGet
  probe above, before (3 failures in 4) and after (4 CLEAN in 4).
