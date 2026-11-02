# Install with the project's package manager

## Intent

Both auto-detected Node legs (ESLint in `quality.Check`'s lint pass, Vitest in
its test pass) installed every project with `npm install`. In a pnpm or yarn
repository npm ignores the lockfile, resolves every range afresh and lints or
tests a dependency tree nobody committed. Nothing said so: the leg reported the
ESLint and vitest versions it found, which were versions the team never chose.

Measured on changesets/changesets (pnpm, `packageManager: pnpm@11.13.1+sha512…`)
before this change: the npm install failed, and the leg was a named non-run.
After it, on node:24-alpine: `pnpm install --frozen-lockfile` succeeded through
corepack, ESLint 10.10.0 from the lockfile linted the tree, and vitest counted
129 tests.

## Chosen approach

`nodeinstall.go` (untagged, unit-tested) decides; `nodedetect.go` reads the
project's `package.json`, its directory listing and `yarn.lock`.

- **Detection order.** `packageManager` in `package.json` first, then the
  lockfile (`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml`,
  `yarn.lock`, `bun.lock[b]`). No lockfile and no field is npm, as before.
- **Disagreement is a named non-run, never a guess.** Two managers' lockfiles
  with no `packageManager`; a `packageManager` whose own lockfile is missing
  while another manager's is present; yarn berry (`yarn.lock` with
  `__metadata:`) without `packageManager`, since corepack would otherwise
  choose its version; bun, which cicd does not install. A lockfile from another
  manager beside a matching one is a warning naming the ignored file.
- **Frozen installs, scripts off.** `npm ci --ignore-scripts` with a lockfile,
  `npm install --ignore-scripts` without one; `pnpm install --frozen-lockfile
  --ignore-scripts`; yarn classic `--frozen-lockfile --ignore-scripts`; yarn
  berry `--immutable` with `YARN_ENABLE_SCRIPTS=false`. pnpm and yarn come
  from corepack (`COREPACK_ENABLE_DOWNLOAD_PROMPT=0`).
- **Resolution follows the manager.** Binaries resolve with `npx --no --`
  (npm, pnpm, yarn classic: `node_modules/.bin` up through the workspace root,
  never fetched) or `yarn` (berry, whose Plug'n'Play tree has no
  `node_modules`); module lookups with `node` or `yarn node`.
- **The install exit is recorded and named.** Every remedy says which install
  failed (`pnpm install exited 1`), and a corepack install adds the cause npm
  does not have: corepack itself could not fetch the manager.
- **Warnings name what cicd could not hold fixed:** a `packageManager` without a
  `+sha512` hash (corepack does not verify the download), a version corepack
  chose because none was declared, and no lockfile at all.
- **The private feed reaches pnpm.** pnpm 11 ignores `NPM_CONFIG_REGISTRY`
  (measured against pnpm 11.19.0 with a local registry logging requests);
  `PNPM_CONFIG_REGISTRY` and `PNPM_CONFIG_//<host>/:_authToken` are set beside
  the npm pair, both nerf-darted to the feed's host.
- **The image moves to node:24-alpine.** node:20 is past end of life, and
  corepack is gone from Node 25, so renovate.json holds the group below 25.

## Rejected

- **Inject the feed token into yarn.** `YARN_NPM_AUTH_TOKEN` is not scoped to a
  host: a scope `.yarnrc.yml` routes to another registry would be sent the same
  token. A yarn project gets no feed, and a warning says so.
- **Add `@vitest/coverage-v8` to pnpm and yarn installs.** `pnpm add` and
  `yarn add` rewrite `package.json` and the lockfile, and fail against a frozen
  install. Such a project runs without coverage, and the warning
  (`provider-undeclared`) tells it to declare the provider.
- **Run lifecycle scripts.** A project whose tests need its own `postinstall`
  (changesets builds its workspace links in one) is exactly what the witnessed
  leg (`--test-cmd`) is for; running every dependency's install scripts in the
  auto leg is the supply-chain door `--ignore-scripts` closes.

## Not claimed

- **Workspace members are not installed on their own.** Node project detection
  lints and tests the topmost `package.json`, which is the workspace root, so
  the install always runs where the lockfile is. A leg that runs inside a member
  will need the walk up to the lockfile.
- **Yarn classic and corepack's own registry are unproven against a private
  feed.** Corepack fetches the manager from registry.npmjs.org
  (`COREPACK_NPM_REGISTRY` is not set); a network that blocks it fails the
  install, and the remedy names that cause.

## Expected result

At `--fail-on NONE` on node:24-alpine:

- `testdata/node-app` (npm, `package-lock.json`): `npm ci`, one test, coverage
  75, ESLint findings as before.
- `testdata/app-workspace` (`packageManager: pnpm@11.19.0`): pnpm installed by
  corepack, ESLint 9.39.5 from the lockfile, the unpinned-`packageManager`
  warning on both legs, and a vitest non-run (the fixture declares no vitest)
  whose remedy does not mention `npm install`.
- changesets: pnpm install succeeds, ESLint 10.10.0 runs, vitest counts 129
  tests.

`src/quality/nodeinstall_test.go` holds the detection table, the install lines,
the exec forms, the feed environment, and an `sh -n` parse of every script
variant — which caught an apostrophe in a message breaking the single-quoted
`echo` that writes it.
