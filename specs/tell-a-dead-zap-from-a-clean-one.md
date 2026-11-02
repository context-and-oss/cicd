# Tell a dead ZAP from a clean one

## Why

`webDisclosureWarnings` decided whether a scan had found nothing by reading the
readiness probe:

```go
if p.Readiness.OK && p.URLsWithAlerts == 0 {
    out = append(out, "dast: NO ALERTED URL — the scan completed and no URL produced an alert. …")
}
```

The probe runs *before* ZAP, against the application, and succeeds in both of
the cases that line has to tell apart. A ZAP that dies during startup and a
target with nothing to find produce the same zero alerted URLs behind the same
`Readiness.OK`.

So the sentence shipped on runs where ZAP never started. Measured on this
repository's own `composite-smoke-dast` job, one run on `main` —
the same `comment.md`, seven lines apart:

```
| security / zap | ⚠️ errored | not stated | 0 | 1 | 5 |

- dast: NO ALERTED URL — the scan completed and no URL produced an alert.
  The readiness probe answered 200 at http://app-under-test:18081/health,
  so the target was reachable; …

- zap: did not run (exit 3): ERROR [Errno 5] Failed to connect to ZAP after
  600 seconds [last log line: 36179 [ZAP-daemon] INFO
  org.zaproxy.zap.DaemonBootstrap - ZAP 2.17.0 terminated.]
```

`ZapExitCode` was in the same struct, four fields above the guard, under a
comment reading "recorded because ZAP's exit codes carry information the alert
list does not — and because throwing it away is the defect this work exists to
fix." Nothing read it.

This is the founding doctrine failing inside the module that enforces it, and
the failure was not theoretical: it was on `main`, in the output of the smoke
whose job is to prove the DAST leg is honest.

Two things came out of trying to work out *why* ZAP died, and neither could be
answered from the evidence:

**The log was thrown away.** `zapFailureDetail` reduces each stream to
`lastNonEmptyLine`. On every startup failure observed, that line is
`… DaemonBootstrap - ZAP 2.17.0 terminated`, which is the consequence. `web.go`
read both streams whole, built the one-line summary, and dropped the rest.
Failures across Azure DevOps and GitHub runs produced the same last line
and no cause. A further failure arrived while this fix was being written, on `main`,
and is the sharpest statement of the problem in the set: ZAP's own
log says `33110 [ZAP-daemon] INFO org.zaproxy.zap.DaemonBootstrap - ZAP 2.17.0
terminated`, so the daemon was gone **33 seconds** in, and the wrapper then sat
waiting out the full `-T 15` before reporting `Failed to connect to ZAP after
900 seconds`. Fifteen minutes of wall clock bought one line that names the
minute the wrapper gave up and nothing at all about the 33rd second. Whatever
the daemon printed on its way down is in the discarded part of the stream.

**The clock was one nobody had chosen.** `zapOptions.MaxDurationMinutes` was
documented as "caps the whole scan (-T)". It does not. Measured in the pinned
image:

```
$ docker run --rm --entrypoint sh ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a… \
    -c 'grep -n -- "-T " /zap/zap-api-scan.py'
112:  print('    -T   max time in minutes to wait for ZAP to start and the passive scan to run')
```

`-T` bounds startup and passive scanning; the active scan is not on it. And
omitting `-T` is not "no budget":

```python
# zap-api-scan.py
timeout = 0
...
wait_for_zap_start(zap, timeout * 60)
zap_wait_for_passive_scan(zap, timeout * 60)

# zap_common.py
def wait_for_zap_start(zap, timeout_in_secs = 600):
    if not timeout_in_secs:
        # if ZAP doesn't start in 10 mins then its probably not going to start
        timeout_in_secs = 600
```

That 600 is where "Failed to connect to ZAP after 600 seconds" comes from, and
why `Dast.run` took 11m0s to produce a non-run: the smoke passes no
`--max-duration-minutes`, so it inherited a ten-minute clock from ZAP.

## Proof

Everything above was read out of the pinned image
(`ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a…`), not recalled.

The measurement that changed the design is `zap_wait_for_passive_scan`:

```python
while (int(zap.pscan.records_to_scan) > 0):
    time.sleep(2)
    time_taken += 2
    if timeout_in_secs and time_taken > timeout_in_secs:
        timed_out = True
        break
if timed_out:
    logging.debug('Exceeded passive scan timeout')
```

A passive scan that runs out of budget stops waiting, and the run proceeds to
collect whatever alerts it has. Nothing marks the report, the exit status is
unchanged, and the notice is logged at DEBUG, which the packaged scans do not
enable. **Partial passive coverage is byte-for-byte a completed passive scan.**

That killed the obvious fix. Bounding the startup wait means lowering `-T`, and
lowering `-T` shrinks the passive-scan budget by the same amount — trading a
loud ten-minute failure for a silent reduction in coverage, which is the exact
failure class this spec exists to close. `-T` is therefore reported, never
changed.

## What changed

**`dastPayload.ScanCompleted`** — set in exactly one place, and only when ZAP
exited a status `zapRunError` accepts *and* the report it left parsed. A partial
report written before a crash satisfies neither. The `NO ALERTED URL` guard
reads it instead of the probe.

**`dastPayload.ZapLog`** — a bounded tail of both streams
(`zapLogTailBytes`, 16 KiB each, cut forward to a line boundary), kept on a
non-run and on a completed scan that recorded an `errors[]` entry anyway.
Carrying it on a *clean* completed run pays the cost on every run for the
benefit of a rare one.

> **Corrected later.** This bullet originally said "kept only on a
> non-run", on the ground that "a completed scan's daemon log is tens of
> thousands of INFO lines about rules that behaved". That is true of a daemon
> that dumped its bootstrap log and false of a finished `zap-api-scan.py`:
> measured against the pinned image over an import of about 500 URLs, stdout
> was under 8 KB of PASS lines and stderr was two lines, the second of which
> was `Number of Imported URLs:` and the count.
>
> The cost estimate was wrong and the consequence was a scan nobody could
> explain. On a completed consumer DAST run — `scanCompleted: true`,
> `zapExitCode: 0`, a nonzero import count but no declared API paths reached
> — `parseZAPScope` read the count out of stderr, `apiReachError` published an
> `errors[]` entry saying the scan had reached nothing, and `zapLogFor`
> discarded the same string three lines later because the scan had completed.
> Whatever the importer had said about the rest of the operations was in those
> bytes.
>
> `zapLogFor` now takes `errored` as well as `completed`, and the call site
> moved below the reconciliation so it sees that verdict. The trigger is
> deliberately the *existence of an error* and not any measure of how much of
> the document was imported: every such measure is a ratio, a ratio needs a
> threshold nobody can defend, and cicd has already reached a verdict for
> stated reasons. `scripts/smoke/dast-shapes.sh` asserts the pairing —
> `zapLog is None or errors` — rather than the bare absence it asserted before.

**`dastPayload.StartAndPassiveBudgetSeconds`** and
**`StartAndPassiveBudgetDefaulted`** — the clock ZAP actually ran against,
including the 600 seconds it substitutes when cicd passes no `-T`, and whether
that number came from the consumer or from ZAP.

**`startAndPassiveBudgetWarning`** — `dast: PASSIVE SCAN BUDGET NOT SET`, emitted
only when the budget was inherited.

**`zapOptions.MaxDurationMinutes`'s doc comment** — corrected. It said the flag
caps the whole scan.

**`scripts/smoke/dast-shapes.sh`** — asserts `scanCompleted is True` on every
shape that scanned, that `NO ALERTED URL` never appears without it, and that a
clean completed scan carries no log tail.

## Decisions

**The budget line fires only when nobody chose the budget.** The alternative was
a line on every run, since the overrun is always silent and every run is in the
same position. It was rejected because
`TestWebDisclosureIsSilentWhenThereIsNothingToDisclose` asserts that a
configured, clean, container-source run discloses *nothing at all*, on the
stated ground that "a line on every run is a line a reader stops seeing" — a
ruling this file had already made, in this file, about this kind of line. The
surprising case is the inherited clock, and that is the one that speaks.

**No watchdog.** True fail-fast means noticing the daemon has exited while the
packaged script is still polling for it, which means a process watcher inside
`zapRunScript`. It is not here: the daemon also exits normally at the end of a
scan, while the script is still writing its report, so a watcher that gets the
grace period wrong kills healthy runs. That is a change that deserves its own
smoke evidence rather than a ride on a correctness fix.

**No retry.** A retry that silently succeeds converts a measurable flake rate
into an invisible one, which is this document's subject. If one is added, the
attempt count belongs in the envelope.

**`ScanCompleted` is a bool, not a pointer.** Its zero value is the safe answer:
a payload nobody filled in reads as "did not complete", and every disclosure
that reads it stays silent. This is the opposite choice from
`CoverageDocumentsMerged`, where nil and 0 are different facts.

## Known residue

**A consumer-chosen budget can still be exceeded silently.** `--max-duration-minutes 15`
gets no warning, and a passive scan that runs past 900 seconds is as invisible as
one that runs past ZAP's 600. cicd cannot detect it — the signal is a DEBUG log
line the packaged scans do not enable, and `records_to_scan` is not in the
report. The number is now in the envelope on every run, so the question can at
least be asked across envelopes; nothing in cicd asks it.

**The flake itself is not diagnosed.** Three failures, cause unknown. This change
is what makes the next one diagnosable rather than a fix for the failure. The
existing note in `zapFailureDetail` describes an OOM kill during `DomXssScanRule`
mid-scan; the failures here are api mode against a three-operation fixture,
dying at startup, so that diagnosis is not reused.

**The container's exit state is still unread.** `zapFailureDetail`'s comment
records that a measured OOM kill showed `OOMKilled=true` on the container while
neither stream said so. Dagger exposes no such field, so reading it would mean
leaving the Dagger API; not attempted here, and named so the next reader does
not assume it was considered and rejected on merit.
