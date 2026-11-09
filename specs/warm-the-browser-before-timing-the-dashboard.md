# Warm the browser before timing the dashboard

## Why

`TestDashboardTreatsEvidenceAsTextInBrowser` launches headless Chrome once per
subtest under a 30-second budget. It failed a pull request that did not touch
the pages module. The `clean` subtest was killed at 30 seconds with nothing on
stderr but D-Bus connection noise, and the `hostile` subtest that followed
passed in 10 seconds. On other recent runs the same `clean` subtest took about
1, 2, 1 and 11 seconds.

The shape points at the disk rather than the page. Hosted runner disks are
filled lazily on first access, so the first launch reads Chrome and its
libraries off a cold disk, and the second launch finds part of them already
cached. Reproduced on Linux Chromium with the page cache dropped and block reads
throttled to 8 MB/s, the result was the same in each round:

| launch | before | after |
|---|---|---|
| warm-up (new) | — | 46s |
| `clean` | killed at 30s | 0.4s |
| `hostile` | 16s | 0.3s |

Dropping the page cache was the only change between rounds, so the first launch
paid for the read, not the dashboard. CPU contention alone, at half a CPU with
four busy loops, slowed every launch to 5 to 16 seconds but never hung one.

## The mechanism

`src/cross-cutting/pages/render_browser_test.go` now calls `warmUpBrowser`
before the timed subtests. It renders a local page with text and a script under
a 3-minute budget, so the browser, renderer, script engine and fonts are read
before any timing that matters, and it logs how long that took. The dashboard
launches keep their 30-second budget, because on a warm browser that budget is a
hang guard for the dashboard and nothing else.

The warm-up fails rather than skips: a browser that cannot render an empty page
within 3 minutes cannot run the regression either, and in CI a regression that
did not run must not read as one that passed. Every assertion on the dashboard
DOM is unchanged. With a text sink switched to `innerHTML`, `hostile` still
fails with "evidence executed JavaScript in the dashboard".

`dumpDOM` now sets `WaitDelay` on the browser command, so that after a timeout
kill the test waits at most 5 seconds for the output pipes instead of waiting on
a renderer child that outlived the browser process.

## Rejected

- **Raising the per-page budget to several minutes.** This closes the failure
  too, but it turns the hang guard for the dashboard into a cold-disk allowance
  for every launch. A real hang would then cost minutes per subtest, and nothing
  would show whether the time went to the disk or the page. We chose the split
  because each budget then guards one thing.
- **Retrying a launch that timed out.** The retry would succeed because the
  first attempt warmed the cache, so it repairs the symptom while hiding the
  cause. It would also give an intermittent hang in the dashboard a second
  chance to pass.
- **Startup flags such as `--disable-dev-shm-usage` or a null D-Bus address.**
  None of them addresses a cold read of the binary. The reproduction above
  produced the 30-second kill with D-Bus left exactly as it was, and removed it
  by warming the page cache alone.

## Traps

- **Removing the warm-up because it looks redundant.** On a warm developer
  machine it costs about a second and changes nothing. Its value only shows on a
  fresh hosted runner.
- **Warming up with `--version` or `about:blank`.** `--version` starts no
  renderer, and `about:blank` runs no script and lays out no text, so part of
  the cold read would still land on the first timed page.
- **Retrying a launch inside the subtests** brings back the masking described
  under Rejected.
