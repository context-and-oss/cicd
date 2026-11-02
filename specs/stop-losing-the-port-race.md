# Stop losing the port race, and say which failure it was

Two unrelated infrastructure faults took CI red on 2026-09-14, in the same run,
on a branch whose code was green on the run before it and green
again on a re-run with no change. Both were real non-runs, both were correctly
reported as failures, and neither told the reader what had actually happened.

They are fixed together because they are the same shape of problem: a step that
could not run, wearing the face of a step whose code is wrong.

## Why

### ZAP was drawing its proxy port from a lottery

`zap_common.py` in the pinned image picks the port ZAP's proxy will listen on
like this:

```python
def get_free_port():
    while True:
        port = randint(32768, 61000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not (sock.connect_ex(('127.0.0.1', port)) == 0):
            return port
```

It draws a random number, asks whether anything answers on it at that instant,
and returns it. It never binds. Nothing is reserved. `zap-baseline.py` is candid
about what this is:

```python
# Choose a random 'ephemeral' port and check its available if it wasn't specified with -P option
if port == 0:
    port = get_free_port()
```

The range it draws from — 32768-61000 — is the kernel's own ephemeral range,
which in the pinned image is exactly `32768 60999`. That is the pool the kernel
hands to every outbound connection and to every service that binds port 0.

The window between the probe and the bind is not small. ZAP spends about thirty
seconds auto-updating add-ons before the proxy comes up, opening dozens of
outbound HTTPS connections to github.com, and the OAST add-on binds an ephemeral
port of its own on the way. Lose the race and ZAP does not degrade — it exits.

### A dropped connection read as a broken module

`dagger develop` generates a module's SDK by fetching Go modules, so it fails
for two unrelated reasons that look identical from outside the step: the code is
wrong, or the network is. There was no retry and no classification, so a single
HTTP/2 stream reset from `sum.golang.org` failed a matrix cell with

```
Error: failed to apply generated code: exit code: 1
```

which reads as "your module does not compile".

## Proof

### The ZAP failure, from the run's own evidence

The envelope's `zapLog.stderr`, verbatim:

```
28227 [ZAP-DownloadInstaller] INFO  org.zaproxy.addon.oast.services.callback.CallbackService - Started callback service on 0.0.0.0:35627
...
30369 [ZAP-daemon] WARN  org.zaproxy.addon.network.ExtensionNetwork - Failed to start the main proxy: java.net.BindException Address already in use
30369 [ZAP-daemon] ERROR org.parosproxy.paros.CommandLine - Terminating ZAP, unable to start the main proxy.
34683 [ZAP-daemon] INFO  org.zaproxy.zap.DaemonBootstrap - ZAP 2.17.0 terminated.
```

35627 is inside the ephemeral range; so was whatever the proxy had been promised.
The daemon was dead at t=30.4s. The wrapper did not notice, and spent its full
600-second budget connecting to it:

```
"zapExitCode": 3,
"scanCompleted": false,
"scanDurationSeconds": 651,
"stdout": "ERROR [Errno 5] Failed to connect to ZAP after 600 seconds\n"
```

`-P` is universal across the three packaged scans, unlike `--autooff`. Measured
on the pinned image:

| script | getopt string |
|---|---|
| `zap-baseline.py` | `t:c:u:g:m:n:r:J:w:x:l:hdaijp:sz:P:D:T:IU:` |
| `zap-api-scan.py` | `t:f:c:u:g:m:n:r:J:w:x:l:hdaijSp:sz:P:D:T:IO:U:` |
| `zap-full-scan.py` | `t:c:u:g:m:n:r:J:w:x:l:hdaijp:sz:P:D:T:IU:` |

### The develop failure, from the same run

```
go: dagger.io/dagger@7058e9313c720d82c6a07fefb6ce3fab60c7ec4e: verifying module:
reading https://sum.golang.org/tile/8/0/x205/155: stream error: stream ID 23;
INTERNAL_ERROR; received from peer
```

That sentence sat roughly eight hundred lines into a Dagger TUI dump. The
step-level output carried none of it.

The classification proved out on both halves: a re-run of the two failed jobs
with identical code went green, and the sum.golang.org text and a real
`undefined: Security` codegen failure are now the two named fixtures in
`scripts/tests/test_dagger_develop.py`.

## What changed

**`src/security/webmode.go`** gained `zapProxyPort = 8090` and appends
`-P 8090` to every scan, in every mode. A port below 32768 cannot be drawn by
`get_free_port()` and is never handed out by the kernel as an ephemeral port, so
that draw is skipped entirely.

**That is a real race and it is not the one this spec was written about.** The
sentence that used to close this paragraph — "the scan container runs one scan
and exposes no ports, so there is nothing else in it to collide with" — is
false, and so is the diagnosis it rested on. See **Correction: what actually
collided** below. `-P` stays because the `get_free_port()` draw is a genuine
hole that nothing else here closes; it is no longer claimed to be the fix.

**`src/security/webmode.go`** also appends `-z "-silent"`, and
**`src/security/zapaddons.go`** (new) pins the one add-on that flag would
otherwise cost. This is the fix. `-silent` stops ZAP from contacting the
marketplace at startup; the pinned `pscanrulesBeta-beta-50.zap` (596,114 bytes,
sha256 `a979f7cd…92e921b`) is fetched by Dagger, digest-verified in the
container and copied into `/zap/plugin` **before** ZAP starts, so the rule set
is unchanged. Measured against the pinned image on a fixed target:

| run | add-ons downloaded | passive rules loaded |
|---|---|---|
| as shipped | 73 | 67 |
| `-silent` alone | 0 | 61 |
| `-silent` + the pinned add-on | 0 | **67, rule for rule identical** |

The six rules `-silent` alone costs are 10026 HTTP Parameter Override, 10049
Content Cacheability, 10063 Permissions Policy Header Not Set, 10099 Source Code
Disclosure, 10110 Dangerous JS Functions and 90004 Cross-Origin-Resource-Policy
Header Missing or Invalid. Two of them fired on the measurement target, so the
loss was not theoretical — which is why the add-on is pinned rather than the
narrowing being accepted and named.

**`src/security/zapscript.go`** stages and verifies it, and writes one of four
statuses (`ok`, `missing`, `mismatch`, `unreadable`) to a file Go reads back.
`missing` and `unreadable` are `warnings[]` entries naming the six lost rules;
`mismatch` is an `errors[]` entry quoting the expected digest and the URL. An
unrecognised status reads as `missing`, never as `ok` and never as an
accusation.

The fourth status was not foresight. `sha256sum -c` answers exit 1 both for a
file whose digest differs and a file it could not open; Dagger mounts an HTTP
file `0600 root:root`; the pinned image runs as uid 1000(zap). The first smoke
run of this code therefore published **PINNED ADD-ON REJECTED** — that GitHub
had served different bytes — about an artifact whose digest was in fact correct,
and a reader would have gone looking at the release assets. Two changes, because
either alone leaves the trap set: `WithMountedFile` passes `Owner:
zapContainerUser`, and the shell takes the digest as a *value* and compares it
in a `case`, so only a successful read can accuse the bytes.

**`scripts/ci/classify-dagger-develop-failure.sh`** answers one question about a
captured failure: is this the module chain failing to fetch, or the module
failing to build? A separate script for the reason `classify-push-rejection.sh`
gives — it is a regex against wording we do not own, so it is driven by real
captured output in a test rather than rotting inside a workflow condition.

**`scripts/ci/dagger-develop.sh`** retries only what the classifier calls
retryable, on the `0 5 15 30` backoff, and names which kind of failure it was
when it gives up. Both `::error::` messages say what to do next, and neither
says it about the wrong layer.

**`.github/workflows/ci.yml`** routes all five `dagger develop` sites through
the wrapper. The matrix site passes `"$MODULE"` through the job's env rather
than splicing `${{ matrix.module }}` into the command line.

## Decisions

**Pin the port rather than retry the scan.** A retry would have worked — the
race is lost maybe one run in twenty — but it would pay a ten-minute ZAP startup
to re-enter the same lottery, and it would leave the failure in the system to be
rediscovered. `-P` removes the draw entirely. The cost is that cicd now owns a
port number, which is why the constant carries the measurement that justifies it
and a test refuses any value inside the ephemeral range.

**8090, not 8080.** ZAP's own documented default is 8080, and using it would
read as idiomatic. It is also the port most consumer applications listen on, and
this module composes target URLs against consumer ports — a collision would be
between two things cicd wrote, in an error message about a port. 8090 is
outside the ephemeral range and outside the privileged range.

The third clause this decision used to carry — "not a default anything else here
reaches for" — was wrong. The pinned image reserves 8090 in three places of its
own, Webswing among them. Nothing in the scan container starts them, so 8090 is
not the collider here and the choice stands; but it was justified on a property
it does not have, and a reason that is false is worth no less attention for
having reached the right number.

**Retry only fetch faults; never retry a compile error.** Blind retry is the
easier shape and the wrong one. `test_push_rejection.py` records what it costs:
a release job that treated every rejection as retryable spent five attempts
re-deriving a version bump against a ruleset refusal the remote had explained on
the first try. A compile error gets one attempt and a message.

**The classification cannot produce a green.** This is the property that makes a
regex against someone else's wording acceptable here. A fetch fault misread as
permanent is reported at once; a compile error misread as a fetch fault is
retried three times and then reported. Both are red. The classifier chooses the
message and the budget, never the verdict — so a Go toolchain rewording costs a
worse message, not a false pass.

**`PIPESTATUS[0]`, not the pipeline's status.** The wrapper tees dagger's output
so it reaches both the log and the job console, and `tee` succeeds whatever it
is piped. `set -o pipefail` is set and would in fact carry the failure through,
but a develop that reports success because the tee worked is this repository's
founding failure mode, in the one step every later `dagger call` depends on. It
must not rest on a single shell option staying set, so the test drives the
wrapper with a failing fake `dagger` on PATH and asserts a non-zero exit.

**Retry is not graceful failure.** A `dagger develop` that could not generate an
SDK stays red, at every budget. Softening it would let every subsequent
`dagger call` in the job run against a stale or absent SDK — a step that could
not do its work reading as a step that did. The retry narrows which reds are
real. It never turns one green.

## Known residue

**`make develop-all` still calls `dagger develop` directly.** It is a local
convenience target where a failure is immediately visible to the person who ran
it and retried by hand, so it keeps the blast radius of this change to CI. A
developer hitting a sumdb blip locally still gets the cryptic message.

**The `-P` half of the ZAP fix is argued, never observed.** The
`get_free_port()` race is lost intermittently, so a green run proves nothing
that a green run before the change did not also prove. What is proven is the
mechanism: `-P` skips the draw outright, and the port chosen is outside every
range that function and the kernel draw from. The assertion that would fail on a
regression is `TestTheProxyPortCannotBeDrawnFromTheEphemeralRange`, not a CI
run. The `-silent` half is different: it was measured directly, and the
`ExtensionNetwork` reload it removes cannot happen in a process that downloads
nothing.

**Nothing detects a ZAP that died after startup.** `zapRunError` classifies exit
3 as a non-run, which is why this failure was legible at all. But the wrapper
still spends its whole `-T` budget connecting to a daemon that terminated
seconds in, so a startup failure costs the same wall clock as a real scan. That
is ZAP's wrapper, not cicd's, and cicd reads the corpse correctly; it is noted
because "it took ten minutes" was the least informative part of the signal.
