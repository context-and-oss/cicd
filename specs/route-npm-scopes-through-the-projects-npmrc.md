# Route npm scopes through the project's .npmrc

## Why

`--npm-feed-url` makes the private feed the registry for every package.
`withNodeFeed` sets `NPM_CONFIG_REGISTRY` and `PNPM_CONFIG_REGISTRY` to the feed
and binds the token to the feed's nerf dart. That works only for a feed that
proxies the public registry, because every public dependency is then requested
from the feed too.

Some package hosts have no such upstream. A host that serves only its own
organisation's packages answers 404 for a public package such as `lodash`, with
or without a token, so pointing the whole install at it fails the install on
the first public dependency. A consumer moving to such a host could not use
`--npm-feed-url` at all: the token arrived, and so did a registry that could not
serve the tree.

What a consumer wants instead is the split npm already supports in an `.npmrc`:
`@example-org:registry=https://npm.feed.example/` for the private scope, and the
public registry for the rest. Measured with npm 11.19.1 and pnpm 11.19.0 against
a local registry that logged every request and its `Authorization` header:

| Setup | npm | pnpm |
|-------|-----|------|
| Scoped registry from the environment (`NPM_CONFIG_@example-org:registry`) | scope to the feed with Bearer, public packages to the public registry | not applicable |
| Scoped registry from the environment (`PNPM_CONFIG_@example-org:registry`, `NPM_CONFIG_@…`, lowercase spellings) | not applicable | ignored, everything went to the public registry |
| Project `.npmrc` with `@example-org:registry=<feed>`, token only in `*_CONFIG_//<dart>/:_authToken` | scope to the feed with Bearer, public packages to the public registry | scope to the feed with Bearer, public packages to the public registry |
| Same `.npmrc`, no token variable | no `Authorization` header | not measured |

npm also rewrites `_` to `-` in an environment scope key, so `@ex_ample` would
have become `@ex-ample`. Only the last two rows work for both package managers.

## The mechanism

A new optional input, `npm-feed-routing` (`npmFeedRouting` on the modules):

- `registry`, or unset: the existing behaviour. Nothing changes for a caller that
  never sets it.
- `npmrc`: `nodeFeedEnv` returns the two token keys and no registry variables.
  The project's own `.npmrc` decides which packages reach the feed, and the
  token applies to exactly the host the feed URL names.

The same container wiring serves both modes, so `withNodeFeed` stays the single
place the feed reaches a Node container (`src/quality/nodedetect.go`).
`validateNpmFeedRouting` in `src/quality/feeds.go` refuses an unknown value and
refuses `npmrc` without `npm-feed-url`, because that combination would change
nothing and read to its author as a setting that took effect. Check and Test
make the refusal through `validateCheckInputs` and `validateTestInputs`; Prepare
and Collect make it next to `validateFeedCredentials`.

A missing route is the likely mistake in `npmrc` mode, and it fails late and
far from its cause: a 404 naming a private package. The auto Node legs read the
`.npmrc` beside the project's `package.json`, the file npm and pnpm both read
for an install run there, and `nodeFeedRoutingWarning` says so when no registry
line in it reaches the feed. `npmrcRoutesTo` matches by nerf dart and path
prefix, the way npm decides whether a token applies to a request, and counts a
value that expands a variable as routed instead of warning on a file it cannot
resolve.

The input is threaded through `quality`, `build.BuildArchive`, `stage-2`, the
commit and precommit composites, the three reusable workflows, `cicd-prepush` and
the templates. The workflows pass `--npm-feed-routing` only when it is set, so a
workflow pinned to a module release without the flag keeps working.

## Rejected

- **A cicd input naming the scopes** (`npm-feed-scopes: @example-org`). Set
  through the environment it reaches npm and not pnpm (measured above). Written
  into a user-level `.npmrc` by cicd it would work for both, but the project's
  `.npmrc` overrides a user-level one, so a project that already routes its
  scopes would be configured twice, once by each owner. The project needs that
  `.npmrc` for local installs anyway.
- **Detect the mode from the project's `.npmrc`.** A project that routes a scope
  to the feed while relying on the feed as a proxy for public packages would
  switch behaviour without asking. An explicit input keeps the existing callers
  on the path they were measured on.
- **Make `npmrc` the default.** Every caller whose feed proxies the public
  registry and whose `.npmrc` routes nothing would lose its private packages.

## Traps

- Setting `NPM_CONFIG_REGISTRY` in `npmrc` mode sends public packages to a feed
  that cannot serve them; `TestNodeFeedEnvNpmrcRoutingBindsTheTokenOnly` guards
  it.
- Binding the token under a key with no host (`YARN_NPM_AUTH_TOKEN`, or a bare
  `_authToken`) hands it to every registry the project names, the public one
  included. Yarn still gets no credential in either mode.
- Comparing the feed and the `.npmrc` value as plain strings would warn on a
  trailing slash or a missing scheme, and a warning that fires on a correct file
  teaches readers to skip it.
