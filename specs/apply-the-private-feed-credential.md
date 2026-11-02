# Apply the private feed credential

## The problem

`quality.Check` and `quality.Test` accept `--npm-feed-url/--npm-token` and
`--nuget-feed-url/--nuget-token`, thread them through every leg, and hand them
to the container as Dagger secrets. Neither credential was ever applied.

Both failures look identical from the outside, and identical to passing no
credential at all: the feed answers 401, the install or restore fails, and the
leg reports a *missing linter* or a *failed test suite*. Nothing anywhere says
"your token was ignored". This is the doctrine of the repository — a tool that
could not run must never read as clean — one layer further down, at the
credential: **a credential that could not be applied must never read as no
credential.**

### npm: the auth key was not a nerf dart

```go
WithEnvVariable("NPM_CONFIG_REGISTRY", feedUrl).
WithSecretVariable("NPM_CONFIG_//"+feedUrl+"/:_authToken", feedToken)
```

One string served both env vars, and the two want opposite shapes.
`NPM_CONFIG_REGISTRY` needs a scheme; npm's "nerf dart" — the per-registry key
auth hangs off — is host+path with **no scheme and no trailing slash**. Given the
scheme-bearing URL the registry var demands, the concatenation produced

```text
NPM_CONFIG_//https://pkgs.dev.azure.com/org/_packaging/feed/npm/registry//:_authToken
```

npm deliberately does not normalise config keys beginning with `//`
(`@npmcli/config`: *"don't normalize nerf-darted keys"*), so that key is stored
verbatim, never matches the dart npm computes for the request, and the token is
dropped in silence. The same `//` guard is why the path must survive untouched:
npm's ordinary env-key handling rewrites `_` to `-`, and every Azure Artifacts
feed path contains `_packaging`.

### NuGet: the config declared a source and no credentials

```go
nugetConfig := `... <packageSources><add key="internal" value="` + feedUrl + `" /></packageSources> ...`
ctr.WithNewFile("/root/.nuget/NuGet/NuGet.Config", nugetConfig).
    WithSecretVariable("NUGET_AUTH_TOKEN", feedToken)
```

NuGet reads no `NUGET_AUTH_TOKEN` of its own — that name is a convention of
`setup-dotnet` and of the config's `%NUGET_AUTH_TOKEN%` expansion, nothing more.
With no `<packageSourceCredentials>` block the token was inert. The hard-coded
source name `internal` was a second defect: it shadows the consumer's own source
and breaks any `packageSourceMapping` that routes private packages by name.

Notably, the BYO test path (`byotest.go`) already had this right. The auto-detect
legs (`dotnetexec.go`) had the broken copy — two renderings of one credential,
which is exactly the drift this repository has been bitten by before.

## Measured, on the wire

Not unit tests. A local registry that logs request headers, driven by the
production code path.

**npm**, in cicd's pinned `node:20-alpine`, token delivered through
`WithSecretVariable` exactly as the module does it:

| auth env key | first request to the feed |
| --- | --- |
| `NPM_CONFIG_//http://…/registry//:_authToken` (shipped) | `Authorization: *** NONE ***` |
| `NPM_CONFIG_//…/registry/:_authToken` (`npmAuthEnvKey`) | `Authorization: Bearer ***` |

Dagger scrubbed the secret to `***` in **its own progress log** — the one channel
that test observed. It says nothing about the other channels a token could reach:
a tool's stdout/stderr, the raw-output file the BYO test path harvests, or the
evidence envelope. Those are argued from construction, not measured: the token is
delivered as an environment variable and as a `%NUGET_AUTH_TOKEN%` placeholder
NuGet expands itself, so it never enters a command line, and neither npm nor
NuGet echoes a configured credential. That is a weaker claim than a measurement,
and it is the claim this change is entitled to.

**NuGet**, in the pinned `mcr.microsoft.com/dotnet/sdk:8.0`, against a probe that
challenges with `401 WWW-Authenticate: Basic` the way a private feed does — a
404-only probe proves nothing, because NuGet sends no credential until
challenged:

| config | credential sent on the retry |
| --- | --- |
| shipped (no credentials block) | `Basic Og==` — base64 of `":"`: **empty user, empty password** |
| `nugetCredentialedConfig` | `Basic Y2ljZDpEVU1NWS1OVUdFVC1UT0tFTg==` — `cicd:<token>` |

The old config did not merely skip authentication; it answered the challenge
with nothing, which is why the failure surfaced as "restore operation failed"
and never as a credential problem.

## The change

`src/quality/feeds.go` — untagged, so every byte handed to npm and NuGet is unit
tested:

- `npmAuthEnvKey(feedURL)` — derives the dart (strip scheme, strip `//`, strip
  trailing slashes) instead of concatenating.
- `npmRegistryURL(feedURL)` — normalises the *other* shape, adding `https://`
  when a consumer supplies a scheme-less index URL, which npm rejects outright.
- `nugetCredentialedConfig(sourceName, feedURL)` — one rendering of the
  credentialed config, now shared by `dotnetexec.go` and `byotest.go`.
- `nugetCredentialsElement(name)` — `_xHHHH_` escaping for the credentials
  element name, which is NuGet's own convention. A source legitimately named
  `Company Feed` is an attribute value everywhere else; emitted verbatim as an
  element name it yields `<Company Feed>`, invalid XML, and NuGet then reports a
  syntax error in a file the consumer never wrote.
- `dotnetContainer` takes `ctx` so it can discover the consumer's source name
  (`nugetSourceNameForFeed`) rather than hard-coding `internal`.

Call sites fixed: `lint.go` (ESLint), `test.go` (vitest, `dotnet test`),
`byotest.go` (BYO), `dotnetexec.go` (`dotnet format` + `dotnet test`).

### And the credential must not be applied to the wrong transport

Making the token work raises a question that did not exist while it was inert:
where is it now being sent? npm puts `Authorization: Bearer <token>` on the very
first request, and NuGet answers a `Basic` challenge with
`base64(cicd:<token>)`. Over plain HTTP either is a readable secret on the wire,
and neither tool refuses on the consumer's behalf — cicd is typically handed a
pipeline identity that can read every private feed in the organisation, so
silently downgrading its transport is not a footgun worth keeping.

`validateFeedCredentials` therefore runs at both entry points (`Check`, `Test`),
before any container is built, and **fails** rather than dropping the credential —
a dropped credential is the silent 401 this change exists to remove. A scheme-less
URL is fine (`npmRegistryURL` upgrades it to `https`); an explicit non-https
scheme is refused unless the host is loopback, which keeps the door open for
proving the seam against a local server, exactly as the measurements above did.

The credentials element name is also reversible now. NuGet decodes it
(`XmlConvert.DecodeName`) before matching it to a source, so two names would
previously have decoded to something else and attached the credential to a source
the consumer does not have. That is not a parse error: the credential is not
applied to the intended source, so the restore fails with a 401 — or, where the
feed permits anonymous reads, succeeds without ever using the credential, which
is the outcome that reads as clean while proving nothing:
a literal `_x0020_` inside the name (now escaped `_x005f_`), and any character
outside the BMP (now emitted as its two UTF-16 surrogate halves, because NuGet
decodes each marker into one code unit). `TestNugetCredentialsElementRoundTrips`
asserts the property rather than a table: encode, decode with a mirror of
NuGet's decoder, compare.

## What it unblocks for consumers

A consumer whose dependencies resolve through Azure Artifacts can hand cicd the
build identity, with no PAT to store:

```yaml
env:
  NPM_FEED_URL:   https://pkgs.dev.azure.com/<org>/_packaging/<feed>/npm/registry/
  NPM_FEED_TOKEN: $(System.AccessToken)      # needs Feed Reader on the feed
```

npm's config precedence puts the environment above a project `.npmrc`, so a
stale committed token in the repository cannot shadow the one cicd is given —
which is the point: the credential belongs to the pipeline identity, not to a
file in the tree.

Measured on the consumer before this change: over 90% of
the locked packages resolve through the private feed, `npm install` produced no
`node_modules`, and the Node legs reported `eslint: did not run (exit 127)` and
`vitest failed (exit 1)` — one missing credential, two legs with no verdict.

## Still open

- The ESLint leg discards npm's stdout and stderr
  (`npm install … >/dev/null 2>&1 || true`), so when an install fails the cause
  is absent from the evidence and the remedy text can only guess. A fix should
  keep the install's tail in the envelope.
- `quality` does not report which private feed it authenticated against, so
  evidence cannot distinguish "no feed configured" from "feed configured and
  reachable".
- Redaction is measured for Dagger's progress log only (see above). The raw
  output the BYO test path harvests is not filtered, and the argument that a
  configured credential cannot appear there rests on npm's and NuGet's own
  behaviour rather than on a test. Suppressing raw output whenever a token is
  present was considered and rejected: it would blind exactly the runs that most
  need diagnosis, which is the gap the first item above already describes. A
  scrubber over the harvested output would cover both, and is the fix worth
  building.
- `nugetSourceNameForFeed` reads only the root-level `NuGet.config`. A
  per-project config in a subdirectory can name the same feed differently, and
  NuGet's own scope resolution would then prefer that name; cicd writes a
  user-level config, so the root name is the one that composes with it. Nested
  scope resolution is left undone deliberately rather than half-done.
