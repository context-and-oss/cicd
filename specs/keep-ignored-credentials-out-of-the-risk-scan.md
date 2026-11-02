# Keep ignored credentials out of the risk scan

## Intent

`risk.Scan` reads repository files and sends their contents to a model. Its
collector honoured `.gitignore` only when `/src/.git` was a directory. A Git
worktree has a `.git` *file*, and an export has no `.git` at all, so both fell
back to `find`, whose exclusions did not name `.npmrc` or `credentials.json`.
Reproduced against the production script with synthetic sentinels: an ordinary
checkout collected neither ignored file, the worktree of the same repository
collected both, plus its `.git` pointer. Their bytes became prompt input.

The script was also the one piece of `Scan` no test could reach — it lived in
`scan.go`, which is `//go:build !unit_test` — so the only test of file
collection was a separate Go walker that production never ran.

## Chosen approach

- **Git decides which files exist; nothing guesses.** The collector moved to
  `src/risk/collect.go`, untagged, and is run by `collect_test.go` with `sh`
  and a real `git` over real trees, the root substituted for `/src`:
  - a checkout lists `ls-files --cached --others --exclude-standard`;
  - a worktree or submodule is listed the same way only when the metadata its
    `.git` file names is reachable. Inside Dagger it is not — the pointer names
    a host path that is never mounted — so the scan is refused with the remedy
    (scan the main checkout, or a `git archive` export). Changing `-d` to `-e`
    would have handed git a pointer to nothing;
  - a tree with no `.git` is listed by git against a scratch repository in the
    container's temp directory, so the tree's own `.gitignore` files apply with
    git's semantics and nothing is written into the consumer's directory;
  - no git in the image is a refusal, never a walk.
- **A second layer holds whatever git says.** `sensitivePathParts` names Git and
  other VCS metadata at any depth, npm/yarn/netrc/pypirc/pip/NuGet credential
  configuration, `credentials.*`/`secrets.*` config files, SSH, GnuPG, AWS,
  Azure, gcloud and Kubernetes credential stores, key and certificate files,
  `.env*` and Terraform state. One pattern is passed to the script as an
  argument and compiled in Go; the container drops matches before reading a
  byte and `parseCollected` drops them again. A tracked credential file is
  withheld exactly like an ignored one. Symlinks are never followed — the file
  or any directory above it — because a link's name passes the filter while its
  target need not.
- **The repository being scanned cannot steer its own listing.** Git's
  ownership check has to be opened for a mounted tree, and that check is also
  what stops a repository's own config from running commands, so
  `core.fsmonitor`, the untracked cache and hooks are switched off on the
  command line, inherited `GIT_*` variables are unset, a `core.worktree`
  pointing elsewhere and a `.git` symlink are refused, and a path filter grep
  could not compile stops the scan. A collection with no file in it is an
  error in `Scan`, since a review of nothing reads as a review that found
  nothing.
- **Nothing is installed at run time.** The collector used to `apk add git`
  from the network on each scan, unpinned. It now runs in the gitleaks image
  `security` already pins by digest, because that image ships git
  (`src/risk/images.go`, `scripts/runtime-images.json`).
- **The manifest says which boundary held.** `scan-manifest.json` gains
  `ignore_rules`: `git` or `tree-gitignore`.

## Rejected

- *Fall back to `find` with a longer deny-list.* A deny-list can only refuse
  the names someone already thought of; ignore rules are the consumer's own
  statement of what is local.
- *Collect in Go with a `.gitignore` parser.* A second implementation of git's
  ignore semantics is a second answer to one question.
- *Parse the worktree's `.git` file and guess.* The tracked list and
  `info/exclude` live in the metadata that is not there.

## Proof

`collect_test.go` drives the production script over a checkout with tracked
and ignored credential files and a nested repository, a real worktree with its
metadata reachable, the same worktree with its main checkout moved away (the
Dagger case: refused, nothing listed), an export with stray `.git` and `.hg`
directories, a symlink to a withheld file and a symlinked directory,
filenames with spaces, a repository config carrying `core.fsmonitor` and
`core.worktree`, a `.git` symlink, a filter that cannot compile, and a missing
git. Each asserts that safe source reached the prompt and that no sentinel
reached the container output, the prompt built by `buildScanPrompt`, or the
serialized manifest. Mutations that remove either layer, or route worktrees to
the export path, fail it.

## Residue

These tests prove what the collector enumerates and what reaches the prompt. A
live `dagger call risk scan` was not run here, and no test claims what a model
received. A secret pasted into an ordinary source file is still sent — the
path policy is not a secrets scanner. Ignore rules kept only in another clone's
`info/exclude` or a global excludes file are invisible to an export, which the
risk README says.
