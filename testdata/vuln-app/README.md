# vuln-app — the DAST fixture

A deliberately vulnerable HTTP application. It exists so cicd's own DAST leg can
be proven against a target whose findings are known in advance, instead of
against a third-party host on the public internet — the `scan-web` module-test
cell used to scan `scanme.nmap.org`, whose availability is not cicd's to depend
on and whose unreachability the cell had to tolerate as an expected outcome.

**Do not deploy this. Do not copy it into a real service.** Every defect below
is planted, and the app is reachable only inside a Dagger service binding.

## What it serves

| Path | Purpose |
|------|---------|
| `/health` | Readiness endpoint. Answers `200 {"status":"ok"}` and nothing else — the probe target, deliberately free of planted defects so a readiness failure is never mistaken for a finding. |
| `/` | Landing page. Links to every other path so ZAP's spider reaches them. |
| `/greet?name=` | Reflects `name` into the HTML body **unescaped** — a reflected XSS an active scan finds. |
| `/api/items` | A JSON collection, so the API scan has a real response to work against. |
| `/openapi.json` | The OpenAPI 3.0 document describing the three endpoints, embedded from `openapi.json` so `mode=api` can be driven from a path on the target as well as from a checked-in file, and the two cannot drift. |

## What a scan is expected to report

The planted defects are deterministic — each is a property of the response
itself, so no assertion is a coin flip on timing or on how far a spider got.

Passive (`mode=baseline`, and therefore `api` and `full` too):

- **Content Security Policy Header Not Set** — MEDIUM. No `Content-Security-Policy`.
- **Missing Anti-clickjacking Header** — MEDIUM. No `X-Frame-Options`, and no CSP
  `frame-ancestors` to stand in for it.
- **X-Content-Type-Options Header Missing** — LOW.
- **Cookie Without HttpOnly / SameSite Attribute** — LOW. `/` sets `session` with
  neither.
- **Server Leaks Version Information** — LOW. `Server: vuln-app/0.1.0`, added by
  middleware because Go's `net/http` sends no `Server` header of its own.

Active only (`mode=full`):

- **Cross Site Scripting (Reflected)** — HIGH, on `/greet`.

The HIGH is the load-bearing one. It is the difference between a baseline scan
and a full scan expressed as a finding, so a `full` run that reports no HIGH did
not run a full scan whatever its exit code said — an assertion on the exit code
alone cannot tell those apart.

## Why it is a Go app with no dependencies

`go.mod` requires nothing, so the image builds with no module download and the
fixture cannot fail to start because a registry was unreachable. It is also why
there is no `go.sum` and why the Dockerfile copies only `go.mod`.
