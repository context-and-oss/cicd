# Bind the npm feed token under a name the shell keeps

## Why

The npm feed token was bound as the environment variable
`NPM_CONFIG_//<host>/<path>/:_authToken`. npm accepts that name when it is
exec'd directly, which is how it was proven on the wire. Consumer commands are
not exec'd directly. Every prepare, test, lint and build command runs through
`sh -c`, and on Debian- and Ubuntu-based toolchain images such as
`node:22-bookworm-slim` or the .NET SDK images, `sh` is dash. dash drops every
environment entry whose name is not a shell identifier before it starts a
child. The slashes and the colon disqualify the name, so the token never reached
npm or pnpm. A bash started from that dash does not get it back either.

Measured with a local registry that records the `Authorization` header, through
dash:

| binding | npm | pnpm |
|---|---|---|
| old `NPM_CONFIG_//…:_authToken` env var | none | none |
| `NPM_CONFIG_USERCONFIG` file with `${VAR}` | Bearer | Bearer |
| `PNPM_CONFIG_USERCONFIG` file with `${VAR}` | — | Bearer |
| `NPM_CONFIG_GLOBALCONFIG` file with `${VAR}` | Bearer | none |

A consumer that routed a scope to the feed and passed a valid token saw `E401`
on `npm ci`. The Dagger-level reproduction against the unfixed module recorded
`none` for every request.

## The mechanism

`nodeFeedConfig` in `src/quality/nodeinstall.go` replaces the env-var binding:

- The token is bound as the secret variable `CICD_NPM_FEED_TOKEN`, which is a
  valid shell identifier, so dash and bash both pass it on.
- cicd writes its own npmrc at `/etc/cicd/npmrc`. It holds one line,
  `<nerf dart>:_authToken=${CICD_NPM_FEED_TOKEN}`. The file holds the
  reference, never the value, so the token is in no file and no layer. npm and
  pnpm both expand `${VAR}` in npmrc at read time.
- `NPM_CONFIG_USERCONFIG` and `PNPM_CONFIG_USERCONFIG` point at that file. Both
  names are valid identifiers.
- Registry routing still sets `NPM_CONFIG_REGISTRY` and `PNPM_CONFIG_REGISTRY`.
  npmrc routing sets neither and leaves scope routing to the project's own
  `.npmrc`, as before.

`src/quality/nodedetect.go` applies the file, the variables and the secret in
`withNodeFeed`. The nerf dart comes from `npmNerfDart` in `src/quality/feeds.go`,
the same normalisation the old key used, so the scheme is still stripped and the
`_packaging` path is still kept verbatim. Transport validation is unchanged.
`validateFeedCredentials` also refuses an npm feed URL that contains whitespace
or a control character, because the URL is now written into an npmrc line and a
line break would add a config entry of its own.

`src/quality/nodefeedshell_test.go` is the regression. It runs a command through
the real dash, wrapped the way every consumer command is, against a local
registry, and requires `Bearer` on every request. A control row binds the token
the old way and must arrive with no header; if it does arrive, `sh` was not a
shell that drops the name and the test fails instead of passing vacuously. The
test fails rather than skips when `CI` is set and dash or npm is missing, since
a skipped regression in CI is a regression nobody runs.

The NuGet path needed no change, because its token is bound as
`NUGET_AUTH_TOKEN`, a valid identifier, and referenced as `%NUGET_AUTH_TOKEN%`
from a cicd-written `NuGet.Config`.

## Rejected

- **`NPM_CONFIG_GLOBALCONFIG`.** It would not hide the image's `~/.npmrc`, but
  pnpm ignores it and sent no header in the measurement above. We chose
  userconfig because it works for both package managers.
- **Wrapping the command in bash instead of sh.** bash keeps such names, but it
  is not present on every toolchain image, and the old name still depends on
  every intermediate process forwarding an invalid identifier. A valid name
  removes the dependency rather than moving it.
- **Binding a consumer-chosen variable such as `NODE_AUTH_TOKEN`.** It would
  collide with a consumer's own use of the name, and cicd would then be writing
  a credential into a variable it does not own.
- **Writing the token itself into the npmrc.** Rejected because the file would
  become a layer that holds the secret.

## Traps

- **Project `.npmrc` outranks user config.** A project line
  `<feed dart>:_authToken=…` now beats cicd's token for npm, even when the line
  names an unset variable: npm sends the unexpanded literal. pnpm skips such a
  line and sends cicd's token. `nodeFeedShadowWarning` warns when the project
  `.npmrc` carries a token for the feed's own dart, or any credential for a dart
  below it, and names the key without its value. A `_auth` on the same dart does
  not shadow and does not warn, since npm reads the token first.
- **The image's `~/.npmrc` is hidden** while the feed is configured, because
  `NPM_CONFIG_USERCONFIG` replaces it rather than adding to it.
- **`npm config set` in a consumer command writes into `/etc/cicd/npmrc`.** The
  next leg reapplies `withNodeFeed` and rewrites the file, so such a write does
  not survive into another leg.
- **Reintroducing any env-var name with `/` or `:` in it** reopens the defect on
  every dash-based image while still passing a test that execs npm directly.
  The shell regression exists to catch exactly that.

The rule this records is in
[docs/explanation/doctrine-quality.md](../docs/explanation/doctrine-quality.md).
