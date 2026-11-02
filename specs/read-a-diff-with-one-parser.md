# Read a diff with one parser

## Intent

Two gates scope themselves to the files a change touched, and each read the
supplied `git diff` with a parser of its own. Both parsers were wrong, in
different places, and every error read as a change that touched less than it
did:

- **risk** (`extractChangedPaths`, `src/risk/validate.go`) read only `+++ b/`
  and `rename to`. A `--no-prefix` diff produced no paths, and an empty change
  set was read as "the change touched no infrastructure": a diff that renamed a
  file and edited a Dockerfile came back `NOTHING IN SCOPE`, SKIPPED, passed.
  A deletion-only diff also produced no paths, which fell back to the whole
  tree: the opposite error, failing a pull request on files it never touched.
- **intent** (`changeScope` / `extractChangedPaths`, `src/cross-cutting/intent/extract.go`)
  refused a C-quoted `+++ "b/my spec.md"` with a message that blamed
  `--no-prefix`; missed a binary file entirely (it has no `+++` line), so a pull
  request adding a binary artifact failed presence; and read headers outside
  the header block, so an added content line `++ b/specs/old.md` put an
  artifact the pull request never touched in scope.

## Chosen approach

One untagged `parseDiffPaths` in `diffpaths.go`, byte-identical in both
modules, with its test table byte-identical beside each copy. A `synced_files`
group in `scripts/repo-inventory.json` holds each pair, so `make check-surface`
fails the moment one copy moves without the other.

It reads a diff block by block:

- headers only between `diff --git` and the block's first `@@`,
  `Binary files … differ` or `GIT binary patch`;
- C-quoted paths unquoted (`strconv.Unquote` reads the escapes git writes);
- `--- a/`, `+++ b/`, `/dev/null`, `new file mode`, `deleted file mode`,
  `rename from/to`, `copy from/to`;
- a block with no `---`/`+++` (binary, mode-only, empty file) takes its path
  from the `diff --git` line, split the way git splits it: quoted sides, a
  single space, or two equal halves behind `a/` and `b/`.

It returns the surviving paths (what still exists after the change; intent's
scope and risk's scope) and every touched path in order (intent's coupling
rule, which needs deleted files and rename sources too). A copy's source is not
touched.

Refusals keep intent's established wording, which `scripts/smoke/non-run-matrix.sh`
greps: no `diff --git` header is "not a git diff"; a header path without its
`b/` (checked first) or `a/` prefix "carries no b/ prefix". Risk now refuses
too, with a hard error before the envelope exists, as `resolveInfraScope` does
for a scope it does not know. An empty diff stays "no change set" for both.

## Rejected

- **Teach risk's parser the three missing cases in place.** Rejected because
  two parsers is the defect: intent's had been fixed for no-prefix diffs and risk's had not.
- **A shared Go package.** Dagger modules share no Go module (CLAUDE.md); the
  repository's mechanism for one rule in two modules is a guarded copy.
- **Read the `Binary files A and B differ` line for the path.** Splitting it is
  ambiguous when a name contains ` and `; the `diff --git` line names the same
  path and git itself splits it by the equal-halves rule.

## Expected result

- `diffpaths_test.go` in both modules: modified, added, deleted, rename, copy,
  quoted (space and octal), unquoted path with a space, binary added and
  deleted, a binary payload, mode-only, a content line that looks like a
  header, CRLF, a preamble; refusals for not-a-diff, diffstat, plain diff,
  no-prefix (also with a space, under a `b/` directory, quoted, as a second
  file), mnemonic prefixes, broken quoting, and a header naming no path.
- risk `TestDiffChangeScope`: the review's no-prefix rename plus Dockerfile is
  refused naming the prefix; a deletion-only diff is a known empty scope that
  `planInfraScan` reports as nothing in scope; a quoted Dockerfile path is
  scanned.
- intent's non-run matrix: binary-only and mode-only changes now name their
  file and still put no artifact in scope.
- A one-byte edit to either copy turns `make check-surface` red.
