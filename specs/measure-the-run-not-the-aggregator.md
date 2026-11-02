# Intent: a duration field must measure the run it is printed beside

## Why

The first shadow bundle produced after the evidence aggregator learned to
return by reference rendered this in `comment.md`:

```text
| **Duration** | 0s |
```

It sat directly under a real verdict, findings and a commit SHA.
The run it described had scanned a repository end to end.

`combined-evidence.json` carried a duration of only tens of milliseconds. That was not a
measurement of the run. `buildCombined` stamped the combined envelope with the
moment `Wrap` began and with `time.Since(start)` — how long `Wrap` itself took.
`Wrap` runs *after* every module has finished, so both fields described the
aggregation step, and neither described anything a reader of the artifact
cares about.

This is the standing failure class in its quietest form. Nothing errored, no
tool was skipped, no signal was missing. A field simply named one thing and
measured another, and printed the answer next to figures that were correct —
which is what made it credible. A reader has no way to tell a run that took no
time from a clock that was never started.

The rendering compounded it. `dur.Round(time.Second)` turned that sub-second
duration into `0s`, so the clue — its implausible smallness — was rounded away
before it reached a human. Meanwhile the Teams card kept the milliseconds,
so the two artifacts describing one run disagreed,
and the more honest of the two was the one fewer people read.

## What changed

**The combined envelope is timed from the envelopes it aggregates**
(`combinedSpan` in `src/cross-cutting/evidence/bundle.go`). Its
`timestampUtc` is the earliest module start and its `durationMs` runs from
there to the moment the bundle is assembled. Every module already stamps
`TimestampUTC` with its own start, so the span covers modules run in parallel
and in sequence alike. A sum of per-module durations was rejected: it would
overstate any run whose legs overlap.

**An unstamped envelope cannot poison the span.** A zero `TimestampUTC` means
the module never stamped one; dragging it into the minimum would report a
duration of roughly two thousand years. Those envelopes are skipped. If none
carry a usable stamp, or the earliest stamp is somehow later than now, the
aggregator's own start is used — wrong, but bounded, and preferable to a
number no reader could take seriously.

**One formatter, and it refuses two misleading renderings**
(`formatDuration` in `src/notify/render.go`, used by both the markdown table
and the Teams card). A sub-second duration keeps its milliseconds instead of
rounding to `0s`. A zero or negative duration renders `not measured` rather
than `0s`, because zero is an absent measurement and not a run that took under
a millisecond — `build.NoArtifact` sets `DurationMS` to zero deliberately,
because nothing ran.

## Proof

`TestCombinedSpanMeasuresTheRunNotTheAggregator` reconstructs the failing
shape: three envelopes spanning the run, a `Wrap` that starts near the end,
and a `now` 76ms after it. It asserts the run's span, not the aggregator's.
Reverting `combinedSpan` to the old behaviour fails that test and two others —
the unstamped-envelope guard and the clock-skew guard — while the three cases
that exercise the fallback path pass under both, because there the two
behaviours genuinely coincide.

`TestFormatDuration` pins every boundary, including `76 -> "76ms"` and
`0 -> "not measured"`. `TestBuildCardAndMarkdownAgreeOnDuration` renders one
envelope through both paths and asserts the same string appears in each, so
the two artifacts cannot drift apart again.

Note that the Teams card's output changes for durations over a second: it
previously printed Go's default (`1.5s`) and now rounds like the table (`2s`).
Consistency between the two artifacts was judged worth more than the half
second, and the card gains the `not measured` case in exchange.
