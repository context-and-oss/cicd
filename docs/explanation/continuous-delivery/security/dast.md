# DAST (Dynamic Application Security Testing)

Dynamic analysis tests running applications (black-box testing).

---

## Overview

DAST interacts with your application via APIs or UI to simulate attacker behavior and test actual runtime security.

### What It Detects

| Vulnerability              | Description                             |
| -------------------------- | --------------------------------------- |
| Authentication Flaws       | Weak auth, session issues               |
| Authorization Bypasses     | Privilege escalation                    |
| Injection Attacks          | SQL, command, LDAP injection at runtime |
| Security Misconfigurations | Default credentials, open ports         |
| Sensitive Data Exposure    | Unencrypted data, information leakage   |
| Business Logic Flaws       | Workflow bypasses                       |

### Benefits

- Tests actual application behavior
- Finds runtime-only vulnerabilities
- Language-agnostic
- Tests real attack scenarios

### Limitations

- Slower than SAST (minutes to hours)
- Requires running application
- May miss code-level issues
- Can have false positives

---

## How cicd does it

`security.scan-web` drives OWASP ZAP against a running application, and
`src/composites/dast` wraps it into a pipeline — build (optionally), probe,
scan, aggregate evidence, notify. Neither is wired into `precommit` or
`commit`, and that is the design rather than an omission: an active scan is
minutes to hours of traffic against a live application, which is the wrong
thing to put in front of a merge. DAST runs from its own workflow on its own
cadence — baseline on mainline and nightly, full weekly and on demand.

### Somebody has to start the application, and it matters who

The "requires running application" limitation above is the whole design
problem, because the answer changes what the evidence can honestly claim.

- **cicd starts it** (`--app container`): cicd builds the image from this
  commit's Dockerfile and runs it inside the engine. This is the only shape
  whose evidence can say the scanned code is the code this commit produced.
  It fits one container with one port and nothing beside it.
- **You start it** (`--app service` on the runner, `--app url` somewhere
  routable): covers everything else — a compose stack, a database, a sidecar,
  a staging environment. cicd did not build what it scanned, so the evidence
  says `dast: PROVENANCE NOT ATTESTED` on every run.

Both ship, because a scan of a real running app with no provenance line is
worth considerably more than no scan at all. What is not negotiable is that
the difference is *stated*: the two produce otherwise identical envelopes.

### A scan that reached nothing is not a clean scan

The failure mode that makes DAST dangerous is quiet. An application that never
came up produces a report with zero alerts, and that report is byte-identical
to a scan of a genuinely clean target. So cicd probes the target itself before
scanning — in a different container from ZAP's, because the answer to "could
this be reached" must not come from inside the tool whose silence is under
suspicion — and records the verdict in the envelope either way. A probe that
never got a served response is a **non-run**: `passed: false` at every
threshold, `NONE` included.

The same rule runs through the rest of the surface. A baseline run says it
sent no attack payloads. An unauthenticated scan says it saw the anonymous
surface only. A `--fail-on CRITICAL` says the threshold is unreachable,
because ZAP's maximum risk rating is High and a gate that cannot fail looks
exactly like a gate that passed.

Full parameter surface, evidence payload and disclosure lines:
[Running-app DAST](../../../reference/dast.md). Task-oriented walkthrough:
[Scan a running app (DAST)](../../../how-to-guides/scan-a-running-app.md).

---

## Related Documentation

- [SAST](./sast.md) - Static Application Security Testing
- [Supply Chain Security](./supply-chain.md) - Dependency and container scanning
- [Shift-Left Security](./shift-left.md) - Security integration principles
