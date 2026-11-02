package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

// The collector decides which repository bytes risk.Scan sends to a model.
// It is untagged so `go test -tags unit_test` runs the production script over
// real checkouts, worktrees and exports (collect_test.go) instead of a model
// of it: the version that only honoured .gitignore when .git was a directory
// sent a worktree's ignored .npmrc and credentials.json to the model for as
// long as nothing ran it outside a Dagger session.
//
// Two layers, and neither trusts the other:
//
//  1. Which files exist, answered by git and nothing else. A checkout (.git is
//     a directory) lists `ls-files --cached --others --exclude-standard`. A
//     worktree or submodule (.git is a file) is listed the same way only when
//     the metadata it points at is reachable from inside the container; when it
//     is not — the usual case, since the pointer names a host path Dagger never
//     mounts — the scan is refused, because the repository's own exclude file
//     and tracked list cannot be read and guessing from `find` is what leaked.
//     A tree with no .git at all (an export) is listed by git against a scratch
//     repository outside the tree, so its own .gitignore files apply with git's
//     semantics and nothing is written into the consumer's directory.
//  2. What must never leave the machine whatever git says: Git metadata and
//     credential-file classes, matched by sensitivePathPattern in the container
//     before a byte is read and again in Go on every path the container returns.
//     A credential file that is tracked by mistake is withheld all the same.

// scanBudgetBytes caps the repository bytes one prompt carries;
// scanPerFileBudgetBytes keeps one large file from starving the rest. The
// collector skips a file over the per-file cap before reading it.
const (
	scanBudgetBytes        = 100 * 1024
	scanPerFileBudgetBytes = 16 * 1024
)

// collectRoot is where Scan mounts the source in the collector container.
const collectRoot = "/src"

// Ignore rules the collector applied, recorded in scan-manifest.json so a
// reviewer can see which source-disclosure boundary held for that run.
const (
	// ignoreRulesGit: the repository's own metadata answered — tracked files
	// plus untracked files not excluded by .gitignore, .git/info/exclude or
	// the repository's config.
	ignoreRulesGit = "git"
	// ignoreRulesTreeGitignore: no .git in the tree, so only the .gitignore
	// files inside it applied. An exclude kept in some other clone's
	// .git/info/exclude or a user's global excludes file was not visible.
	ignoreRulesTreeGitignore = "tree-gitignore"
)

// collectModePrefix marks the collector's first output line. File lines always
// carry a tab; this one never does, so no file path can be read as it.
const collectModePrefix = "risk-collect-ignore-rules:"

// sensitivePathParts are the path classes withheld from the model regardless of
// what git lists. Each is a POSIX ERE that RE2 reads identically, matched
// case-insensitively against the repository-relative path.
var sensitivePathParts = []string{
	// Version-control metadata, at any depth.
	`(^|/)\.(git|hg|svn)(/|$)`,
	// SSH, GnuPG and cloud/Kubernetes credential stores, at any depth.
	`(^|/)(\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.config/gcloud)(/|$)`,
	`(^|/)\.docker/config\.json$`,
	`(^|/)id_(rsa|dsa|ecdsa|ed25519)(_sk)?(\.pub)?$`,
	`(^|/)(authorized_keys|known_hosts)$`,
	`(^|/)(kubeconfig(\.[^/]*)?|[^/]+\.kubeconfig)$`,
	`(^|/)application_default_credentials\.json$`,
	// Package-manager and tool credential configuration.
	`(^|/)(\.npmrc|\.yarnrc|\.yarnrc\.yml|\.netrc|_netrc|\.pypirc|pip\.conf|pip\.ini|nuget\.config)$`,
	`(^|/)(\.git-credentials|\.gitconfig|\.dockercfg|\.pgpass|\.my\.cnf|\.htpasswd|\.boto|\.s3cfg|\.terraformrc|terraform\.rc)$`,
	`(^|/)(credentials|secrets)(\.(json|ya?ml|xml|ini|cfg|conf|toml|txt))?$`,
	`(^|/)(gha-creds-[^/]*\.json|\.vault-token)$`,
	// Key, certificate and keystore material.
	`\.(pem|key|p8|p12|pfx|crt|cer|der|jks|keystore|ppk|kdbx|keytab)$`,
	// Environment files and Terraform state/variables.
	`\.env(rc)?(\.[^/]*)?$`,
	`\.(tfstate|tfstate\.backup|tfvars|tfvars\.json)$`,
}

// sensitivePathPattern is handed to the collector script as an argument and
// compiled here, so the container and Go apply one policy, not two copies.
var sensitivePathPattern = "(" + strings.Join(sensitivePathParts, ")|(") + ")"

var sensitivePathRe = regexp.MustCompile("(?i)" + sensitivePathPattern)

// sensitivePath reports whether rel belongs to a class never sent to a model.
func sensitivePath(rel string) bool {
	return sensitivePathRe.MatchString(rel)
}

// collectArgs is the collector's argv: the script, then the source root and
// the sensitive-path pattern as positional arguments, never spliced into it.
func collectArgs(root string) []string {
	return []string{"sh", "-c", collectScript, "risk-collect", root, sensitivePathPattern}
}

// collectScript lists and base64-encodes every scannable file under $1 in one
// exec. Output: the ignore-rules line, then one "<relpath>\t<base64>" line per
// file, priority files first. Exit 1, with the reason on stderr, whenever git
// cannot answer which files exist — never a fallback to an unfiltered walk.
//
// Noise file types (lockfiles, generated code, minified bundles, snapshots,
// tabular data, IDE configs, vendored deps) are dropped so they don't crowd out
// real source files within the prompt budget. MAX_FILE_BYTES must equal
// scanPerFileBudgetBytes (collect_test.go holds it).
const collectScript = `
set -u
ROOT=$1
SENSITIVE_RE=$2
MAX_FILE_BYTES=16384
TAB=$(printf '\t')

refuse() {
  printf 'risk-scan: %s\n' "$1" >&2
  exit 1
}

command -v git >/dev/null 2>&1 ||
  refuse "git is not available in the collector image, so .gitignore cannot be honoured; refusing to scan"
ROOT_REAL=$(cd "$ROOT" 2>/dev/null && pwd -P) || refuse "cannot enter the source directory"

work=$(mktemp -d) || refuse "cannot create a scratch directory"
trap 'rm -rf "$work"' EXIT
# Nothing from the environment or the image's git configuration may change
# which repository is read or what is excluded: no inherited GIT_* variable, a
# scratch HOME, no system config.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT \
  GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM
export HOME="$work" XDG_CONFIG_HOME="$work" GIT_CONFIG_NOSYSTEM=1
# safe.directory is opened because the mounted tree is owned by whoever owned
# it on the host. That check is also what keeps a repository's own config from
# running commands, so the command-running keys git consults while listing are
# switched off on the command line, which outranks the repository's config.
gitc() {
  git -c safe.directory='*' -c core.quotePath=false -c core.fsmonitor=false \
    -c core.untrackedCache=false -c core.hooksPath=/dev/null "$@"
}

# The listing must be of the directory passed as --source: a repository whose
# config points core.worktree elsewhere would list another tree's paths.
same_toplevel() {
  top=$(gitc -C "$ROOT" rev-parse --show-toplevel 2>/dev/null) || return 1
  [ "$(cd "$top" 2>/dev/null && pwd -P)" = "$ROOT_REAL" ]
}

if [ -L "$ROOT/.git" ]; then
  refuse "the source's .git is a symlink, so its repository metadata may not be inside the directory passed to --source and its ignore rules cannot be trusted. Pass the checkout itself as --source, or a 'git archive' export"
elif [ -d "$ROOT/.git" ]; then
  rules=git
  same_toplevel ||
    refuse "git does not place the checkout's work tree at the directory passed to --source (core.worktree?); refusing to scan"
  gitc -C "$ROOT" ls-files --cached --others --exclude-standard >"$work/list" 2>"$work/err" ||
    refuse "git could not list the checkout ($(head -c 300 "$work/err")); refusing to scan without .gitignore enforcement"
elif [ -e "$ROOT/.git" ]; then
  rules=git
  if ! gitc -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    refuse "the source is a git worktree or submodule (.git is a file) whose repository metadata is not inside the directory passed to --source, so its ignore rules and tracked files cannot be read. Pass the main checkout as --source, or export the tracked files first with 'git archive --format=tar HEAD | tar -x -C <empty-dir>' and pass that directory"
  fi
  same_toplevel ||
    refuse "git does not place the worktree at the directory passed to --source (core.worktree?); refusing to scan"
  gitc -C "$ROOT" ls-files --cached --others --exclude-standard >"$work/list" 2>"$work/err" ||
    refuse "git could not list the worktree ($(head -c 300 "$work/err")); refusing to scan without .gitignore enforcement"
else
  rules=tree-gitignore
  gitc init -q "$work/meta" 2>"$work/err" ||
    refuse "git could not create a scratch repository ($(head -c 300 "$work/err"))"
  gitc --git-dir="$work/meta/.git" --work-tree="$ROOT" ls-files --others --exclude-standard >"$work/list" 2>"$work/err" ||
    refuse "git could not apply the tree's .gitignore files ($(head -c 300 "$work/err")); refusing to scan without them"
fi

# Each filter runs on its own so a grep that could not run (exit 2, a pattern
# it rejects) stops the scan instead of emptying the list without a word.
drop() {
  grep -v -E -i -e "$1" "$work/cur" >"$work/next"
  st=$?
  [ "$st" -le 1 ] || refuse "the path filter could not run (grep exit $st); refusing to scan"
  mv "$work/next" "$work/cur"
}

# A quoted name (control character, quote or backslash) and a trailing-slash
# entry (a nested repository) are not files this scan reads.
grep -v -e '^"' -e '/$' -e "$TAB" "$work/list" >"$work/files"
[ $? -le 1 ] || refuse "the file list could not be read"
{
  for f in README.md CODEOWNERS Dockerfile docker-compose.yml go.mod package.json requirements.txt pom.xml; do
    grep -Fxq -- "$f" "$work/files" && printf '%s\n' "$f"
  done
  cat "$work/files"
} | awk '!seen[$0]++' >"$work/cur" || refuse "the file list could not be ordered"

drop "$SENSITIVE_RE"
drop '\.(png|jpe?g|gif|pdf|zip)$'
drop '(^|/)(findings\.json|decisions\.json|scan-manifest\.json)$'
drop '\.lock$|(^|/)(package-lock\.json|go\.sum)$'
drop '\.(gen\.go|pb\.go|connect\.go|tsbuildinfo|min\.js|min\.css|map)$|_pb\.(go|ts)$'
drop '\.(csv|tsv|parquet|ndjson|snap)$'
drop '(^|/)(__snapshots__|\.idea|\.vscode|vendor|node_modules|dist|\.next|\.nuxt)/'

printf 'risk-collect-ignore-rules:%s\n' "$rules"
while IFS= read -r rel; do
  # A symlink is never followed, at the file or at any directory above it: its
  # name passes the filters above while its target can be any file, including
  # one they withhold or one outside the tree.
  [ -L "$ROOT/$rel" ] && continue
  [ -f "$ROOT/$rel" ] || continue
  dir=${rel%/*}
  if [ "$dir" != "$rel" ]; then
    [ "$(cd "$ROOT/$dir" 2>/dev/null && pwd -P)" = "$ROOT_REAL/$dir" ] || continue
  fi
  size=$(wc -c < "$ROOT/$rel" 2>/dev/null) || continue
  [ "$size" -le "$MAX_FILE_BYTES" ] || continue
  b64=$(base64 < "$ROOT/$rel" 2>/dev/null | tr -d '\n') || continue
  [ -n "$b64" ] && printf '%s\t%s\n' "$rel" "$b64"
done <"$work/cur"
exit 0
`

// errNothingCollected is a collection that cannot be sent: a scan of no files
// would come back with no findings and read as a reviewed repository.
var errNothingCollected = errors.New("risk-scan: the collector returned no file to analyse, so a scan would report nothing about a repository it never read; check that --source is the repository root and holds tracked source files")

// collectedSource is what the collector returned, decoded and re-filtered.
type collectedSource struct {
	ignoreRules string
	files       []scannedFile
	usedBytes   int
}

// parseCollected decodes the collector's stdout into the files the prompt will
// carry, under the budgets. It applies sensitivePath again — the second check
// of the same policy — so a path the container should have withheld never
// reaches the prompt even if the script drifts.
func parseCollected(raw string) collectedSource {
	var out collectedSource
	for _, line := range strings.Split(raw, "\n") {
		if rules, ok := strings.CutPrefix(line, collectModePrefix); ok && out.ignoreRules == "" {
			out.ignoreRules = rules
			continue
		}
		if out.usedBytes >= scanBudgetBytes || line == "" {
			continue
		}
		rel, b64, ok := strings.Cut(line, "\t")
		if !ok || sensitivePath(rel) {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || bytes.IndexByte(decoded, 0) >= 0 {
			continue // skip binary files
		}
		if len(decoded) > scanPerFileBudgetBytes || out.usedBytes+len(decoded) > scanBudgetBytes {
			continue
		}
		out.files = append(out.files, scannedFile{Path: rel, Content: string(decoded)})
		out.usedBytes += len(decoded)
	}
	return out
}

// usable refuses a collection that did not say which ignore rules chose it, or
// that holds nothing to send.
func (c collectedSource) usable() error {
	if c.ignoreRules != ignoreRulesGit && c.ignoreRules != ignoreRulesTreeGitignore {
		return errors.New("risk-scan: the collector did not report which ignore rules it applied, so its output cannot be trusted")
	}
	if len(c.files) == 0 {
		return errNothingCollected
	}
	return nil
}

// buildScanManifest records which files left the machine for the model: paths
// and sizes, never content, and which ignore rules chose them.
func buildScanManifest(c collectedSource, llmMode, scannedAt string) ScanManifest {
	m := ScanManifest{
		SchemaVersion:      "1.0",
		ScannedAt:          scannedAt,
		LLMMode:            llmMode,
		IgnoreRules:        c.ignoreRules,
		BudgetBytes:        scanBudgetBytes,
		PerFileBudgetBytes: scanPerFileBudgetBytes,
		TotalBytes:         c.usedBytes,
		Files:              make([]ScanManifestFile, 0, len(c.files)),
	}
	for _, f := range c.files {
		m.Files = append(m.Files, ScanManifestFile{Path: f.Path, Bytes: len(f.Content)})
	}
	return m
}
