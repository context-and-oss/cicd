package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the production collectScript with sh and a real git over
// real checkouts, worktrees and exports — the only change from Scan is the
// root, a temp directory instead of /src. They prove what the collector
// enumerates and what reaches the prompt and the manifest; they cannot prove
// what a model was or was not sent in a live scan, which needs Dagger.

const safeMarker = "SAFE-SOURCE-MARKER"

// sentinel is the synthetic, test-only content of a file that must never
// reach a prompt. It is not a credential and resembles none.
func sentinel(name string) string { return "SYNTHETIC-SENTINEL-" + name }

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeT(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runCollector runs the production script exactly as Scan does, with root in
// place of /src. env, when set, replaces the environment.
func runCollector(t *testing.T, root string, env []string) (stdout, stderr string, exitCode int) {
	t.Helper()
	args := collectArgs(root)
	cmd := exec.Command(args[0], args[1:]...)
	if env != nil {
		cmd.Env = env
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run collector: %v", err)
	}
	return out.String(), errb.String(), code
}

// listedPaths is what the container side returned, before Go's second check.
func listedPaths(raw string) []string {
	var paths []string
	for _, line := range strings.Split(raw, "\n") {
		if rel, _, ok := strings.Cut(line, "\t"); ok {
			paths = append(paths, rel)
		}
	}
	return paths
}

// sensitiveFiles are written into every fixture: each path is a credential or
// metadata class, and each holds a sentinel. Some are tracked (force-added
// past .gitignore where needed), some only ignored, some nested.
var sensitiveFiles = []string{
	".npmrc",
	"credentials.json",
	"config/.netrc",
	"tools/.pypirc",
	"pkg/.yarnrc.yml",
	"deploy/credentials",
	"deploy/secrets.yaml",
	".aws/credentials",
	"ops/.azure/accessTokens.json",
	"ops/.config/gcloud/application_default_credentials.json",
	"k8s/.kube/config",
	"k8s/prod.kubeconfig",
	"home/.ssh/id_ed25519",
	"home/.ssh/config",
	"home/.docker/config.json",
	".git-credentials",
	"svc/.env.local",
	"certs/server key.pem",
	"infra/prod.tfvars",
	"NuGet.Config",
	"gha-creds-1a2b3c.json",
	"ops/.vault-token",
}

// ignoredOnly are listed in .gitignore and never added.
var ignoredOnly = []string{"local notes.txt", "build/output.txt"}

const fixtureGitignore = "local notes.txt\nbuild/\n.npmrc\ncredentials.json\n.env*\n"

func writeFixtureTree(t *testing.T, root string) {
	t.Helper()
	writeT(t, root, "README.md", "# demo "+safeMarker+"-readme\n")
	writeT(t, root, ".gitignore", fixtureGitignore)
	writeT(t, root, "src/app.go", "package app // "+safeMarker+"-app\n")
	writeT(t, root, "docs/file with spaces.md", safeMarker+"-spaces\n")
	writeT(t, root, "big.txt", strings.Repeat("a", scanPerFileBudgetBytes+1))
	writeT(t, root, "edge.txt", strings.Repeat("b", scanPerFileBudgetBytes-len(safeMarker))+safeMarker)
	for _, rel := range sensitiveFiles {
		writeT(t, root, rel, sentinel(rel)+"\n")
	}
	for _, rel := range ignoredOnly {
		writeT(t, root, rel, sentinel(rel)+"\n")
	}
}

// commitFixture tracks the safe files and every sensitive file — the ignored
// ones forced in, as a mistaken `git add -f` would — so the second layer, not
// .gitignore, is what has to hold them back.
func commitFixture(t *testing.T, root string) {
	t.Helper()
	gitT(t, root, "init", "-q")
	gitT(t, root, "add", "README.md", ".gitignore", "src", "docs", "big.txt", "edge.txt")
	gitT(t, root, append([]string{"add", "-f", "--"}, sensitiveFiles...)...)
	gitT(t, root, "commit", "-q", "-m", "fixture")
}

// assertCollected checks one collector run end to end: the container's list,
// the parsed files, the prompt and the serialized manifest.
func assertCollected(t *testing.T, raw, wantRules string, extraForbidden ...string) {
	t.Helper()
	listed := listedPaths(raw)
	for _, rel := range listed {
		if sensitivePath(rel) {
			t.Errorf("container listed sensitive path %q", rel)
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git/") || strings.Contains(rel, "/.git/") {
			t.Errorf("container listed git metadata %q", rel)
		}
	}
	got := parseCollected(raw)
	if got.ignoreRules != wantRules {
		t.Errorf("ignoreRules = %q, want %q", got.ignoreRules, wantRules)
	}
	paths := map[string]bool{}
	for _, f := range got.files {
		paths[f.Path] = true
	}
	for _, want := range []string{"README.md", "src/app.go", "docs/file with spaces.md", ".gitignore", "edge.txt"} {
		if !paths[want] {
			t.Errorf("safe file %q missing from collection; got %v", want, listed)
		}
	}
	if paths["big.txt"] {
		t.Error("a file over the per-file budget was collected")
	}
	if len(got.files) > 0 && got.files[0].Path != "README.md" {
		t.Errorf("priority file not first: %q", got.files[0].Path)
	}

	prompt := buildScanPrompt(got.files, "{}")
	manifest, err := json.Marshal(buildScanManifest(got, llmModeClaudeCLI, "2026-01-01T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, safeMarker+"-app") || !strings.Contains(prompt, safeMarker+"-spaces") {
		t.Error("positive control: safe source did not reach the prompt")
	}
	forbidden := append(append([]string{}, sensitiveFiles...), ignoredOnly...)
	forbidden = append(forbidden, extraForbidden...)
	for _, rel := range forbidden {
		s := sentinel(rel)
		for name, bytes := range map[string]string{"prompt": prompt, "manifest": string(manifest), "raw output": raw} {
			if strings.Contains(bytes, s) || strings.Contains(bytes, base64.StdEncoding.EncodeToString([]byte(s+"\n"))) {
				t.Errorf("sentinel of %q reached the %s", rel, name)
			}
		}
		if strings.Contains(string(manifest), `"`+rel+`"`) {
			t.Errorf("manifest names withheld file %q", rel)
		}
	}
}

func TestCollectorCheckout(t *testing.T) {
	root := t.TempDir()
	writeFixtureTree(t, root)
	commitFixture(t, root)
	// A nested repository's metadata and contents.
	nested := filepath.Join(root, "third_party", "lib")
	writeT(t, nested, "lib.go", "package lib\n")
	gitT(t, nested, "init", "-q")
	writeT(t, nested, ".git/hooks/creds.sample", sentinel("third_party/lib/.git/hooks/creds.sample"))

	raw, stderr, code := runCollector(t, root, nil)
	if code != 0 {
		t.Fatalf("collector exit %d: %s", code, stderr)
	}
	assertCollected(t, raw, ignoreRulesGit, "third_party/lib/.git/hooks/creds.sample")
}

func TestCollectorWorktreeWithReachableMetadata(t *testing.T) {
	base := t.TempDir()
	main := filepath.Join(base, "main")
	writeFixtureTree(t, main)
	commitFixture(t, main)
	wt := filepath.Join(base, "wt")
	gitT(t, main, "worktree", "add", "-q", "--detach", wt)
	if fi, err := os.Lstat(filepath.Join(wt, ".git")); err != nil || fi.IsDir() {
		t.Fatalf("worktree .git should be a file: %v", err)
	}
	// Ignored files exist only in the worktree's directory, as in the report.
	for _, rel := range ignoredOnly {
		writeT(t, wt, rel, sentinel(rel)+"\n")
	}

	raw, stderr, code := runCollector(t, wt, nil)
	if code != 0 {
		t.Fatalf("collector exit %d: %s", code, stderr)
	}
	assertCollected(t, raw, ignoreRulesGit)
}

// TestCollectorWorktreeWithUnreachableMetadata is the Dagger case: the .git
// file names a host path that is not inside the mount. The main checkout is
// moved away so the pointer dangles exactly as it does inside the container.
func TestCollectorWorktreeWithUnreachableMetadata(t *testing.T) {
	base := t.TempDir()
	main := filepath.Join(base, "main")
	writeFixtureTree(t, main)
	commitFixture(t, main)
	wt := filepath.Join(base, "wt")
	gitT(t, main, "worktree", "add", "-q", "--detach", wt)
	for _, rel := range ignoredOnly {
		writeT(t, wt, rel, sentinel(rel)+"\n")
	}
	if err := os.Rename(main, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}

	raw, stderr, code := runCollector(t, wt, nil)
	if code == 0 {
		t.Fatalf("collector must refuse a worktree whose metadata is unreachable; listed %v", listedPaths(raw))
	}
	if strings.Contains(raw, "\t") {
		t.Errorf("a refused collection must emit no file: %q", raw)
	}
	for _, want := range []string{"worktree", "--source", "git archive"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("refusal %q does not mention %q", stderr, want)
		}
	}
}

func TestCollectorMetadataFreeExport(t *testing.T) {
	root := t.TempDir()
	writeFixtureTree(t, root)
	// Nested metadata directories in an export: a stray .git with config, and
	// a nested .hg store.
	writeT(t, root, "vendor-copy/.git/config", sentinel("vendor-copy/.git/config"))
	writeT(t, root, "vendor-copy/.hg/store/data", sentinel("vendor-copy/.hg/store/data"))
	writeT(t, root, "vendor-copy/ok.txt", "ok\n")

	raw, stderr, code := runCollector(t, root, nil)
	if code != 0 {
		t.Fatalf("collector exit %d: %s", code, stderr)
	}
	assertCollected(t, raw, ignoreRulesTreeGitignore, "vendor-copy/.git/config", "vendor-copy/.hg/store/data")
	if entries, _ := os.ReadDir(root); len(entries) == 0 {
		t.Fatal("fixture vanished")
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		t.Error("the collector wrote a .git into the scanned tree")
	}
}

func TestCollectorNeverFollowsASymlink(t *testing.T) {
	root := t.TempDir()
	writeFixtureTree(t, root)
	if err := os.Symlink(".npmrc", filepath.Join(root, "innocent.txt")); err != nil {
		t.Fatal(err)
	}
	commitFixture(t, root)
	gitT(t, root, "add", "innocent.txt")
	gitT(t, root, "commit", "-q", "-m", "link")

	raw, _, code := runCollector(t, root, nil)
	if code != 0 {
		t.Fatalf("collector exit %d", code)
	}
	for _, rel := range listedPaths(raw) {
		if rel == "innocent.txt" {
			t.Error("a symlink to a withheld file was collected")
		}
	}
	assertCollected(t, raw, ignoreRulesGit)
}

// Without git the collector cannot apply ignore rules, so it refuses; it never
// falls back to an unfiltered walk.
func TestCollectorRefusesWithoutGit(t *testing.T) {
	for _, withRepo := range []bool{true, false} {
		root := t.TempDir()
		writeFixtureTree(t, root)
		if withRepo {
			commitFixture(t, root)
		}
		bin := t.TempDir()
		for _, tool := range []string{"sh", "mktemp", "rm", "mv", "grep", "awk", "head", "wc", "base64", "tr", "cat", "printf"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				continue // a shell builtin
			}
			if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		raw, stderr, code := runCollector(t, root, []string{"PATH=" + bin})
		if code == 0 || strings.Contains(raw, "\t") {
			t.Fatalf("withRepo=%v: collector without git exit %d, listed %v", withRepo, code, listedPaths(raw))
		}
		if !strings.Contains(stderr, "git is not available") {
			t.Errorf("withRepo=%v: refusal %q does not say why", withRepo, stderr)
		}
	}
}

// The Go-side check holds on its own: a line the container should never have
// emitted is still dropped before the prompt.
func TestParseCollectedReappliesThePathPolicy(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	raw := collectModePrefix + "git\n" +
		"src/ok.go\t" + enc("package ok // "+safeMarker) + "\n" +
		".npmrc\t" + enc(sentinel(".npmrc")) + "\n" +
		"a/.git/config\t" + enc(sentinel(".git/config")) + "\n" +
		"home/.ssh/id_rsa\t" + enc(sentinel("id_rsa")) + "\n" +
		"x/.kube/config\t" + enc(sentinel("kube")) + "\n"
	got := parseCollected(raw)
	prompt := buildScanPrompt(got.files, "{}")
	if len(got.files) != 1 || got.files[0].Path != "src/ok.go" || !strings.Contains(prompt, safeMarker) {
		t.Fatalf("files = %+v", got.files)
	}
	if strings.Contains(prompt, "SYNTHETIC-SENTINEL") {
		t.Error("a withheld path reached the prompt through the Go side")
	}
}

func TestSensitivePathPolicy(t *testing.T) {
	for _, rel := range append(append([]string{}, sensitiveFiles...),
		".git", ".git/config", "a/b/.git/HEAD", ".svn/entries", "x/.hg/hgrc",
		".NPMRC", "Credentials.JSON", "_netrc", "pip.conf", ".gitconfig", ".dockercfg",
		"id_rsa", "keys/id_ecdsa.pub", "authorized_keys", "kubeconfig", "kubeconfig.yaml",
		"tls/ca.crt", "store.p12", "app.jks", ".env", "x/.envrc", "state/terraform.tfstate.backup",
	) {
		if !sensitivePath(rel) {
			t.Errorf("sensitivePath(%q) = false, want true", rel)
		}
	}
	for _, rel := range []string{
		"README.md", ".gitignore", ".github/workflows/ci.yml", ".gitattributes", ".gitmodules",
		"src/credentials.go", "src/credentials_test.ts", "docs/secrets-management.md",
		"internal/kube/client.go", "environment.md", "src/key.go", "docker/config.json.md",
	} {
		if sensitivePath(rel) {
			t.Errorf("sensitivePath(%q) = true, want false", rel)
		}
	}
}

// A repository's own config must not run a command while it is being listed:
// the hook could rewrite a harmless file with a credential's bytes before the
// collector reads it, and no path check would see it.
func TestCollectorRunsNoCommandFromTheRepositoryConfig(t *testing.T) {
	root := t.TempDir()
	writeFixtureTree(t, root)
	commitFixture(t, root)
	marker := filepath.Join(t.TempDir(), "fsmonitor-ran")
	gitT(t, root, "config", "core.fsmonitor", "touch '"+marker+"'; false")

	raw, stderr, code := runCollector(t, root, nil)
	if code != 0 {
		t.Fatalf("collector exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("core.fsmonitor from the scanned repository's config ran during collection")
	}
	assertCollected(t, raw, ignoreRulesGit)
}

// A symlinked directory above a listed file is not followed: the file's own
// name passes every filter while its bytes come from wherever the link points.
func TestCollectorNeverFollowsASymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	writeFixtureTree(t, root)
	writeT(t, root, "docs/leak.txt", "placeholder\n")
	commitFixture(t, root) // tracks docs/, leak.txt included
	outside := filepath.Join(base, "outside")
	writeT(t, outside, "leak.txt", sentinel("outside/leak.txt"))
	if err := os.RemoveAll(filepath.Join(root, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "docs")); err != nil {
		t.Fatal(err)
	}

	raw, _, code := runCollector(t, root, nil)
	if code != 0 {
		t.Fatalf("collector exit %d", code)
	}
	if strings.Contains(prompt(raw), sentinel("outside/leak.txt")) {
		t.Fatal("a file under a symlinked directory was read through the link")
	}
}

// A listing of some other tree, or a .git that is a link to metadata that may
// be anywhere, is refused rather than read.
func TestCollectorRefusesARepositoryThatPointsElsewhere(t *testing.T) {
	t.Run("core.worktree", func(t *testing.T) {
		root := t.TempDir()
		writeFixtureTree(t, root)
		commitFixture(t, root)
		gitT(t, root, "config", "core.worktree", t.TempDir())
		raw, stderr, code := runCollector(t, root, nil)
		if code == 0 || strings.Contains(raw, "\t") || !strings.Contains(stderr, "core.worktree") {
			t.Fatalf("exit %d, stderr %q, listed %v", code, stderr, listedPaths(raw))
		}
	})
	t.Run(".git symlink", func(t *testing.T) {
		meta := t.TempDir()
		writeFixtureTree(t, meta)
		commitFixture(t, meta)
		root := t.TempDir()
		writeFixtureTree(t, root)
		if err := os.Symlink(filepath.Join(meta, ".git"), filepath.Join(root, ".git")); err != nil {
			t.Fatal(err)
		}
		raw, stderr, code := runCollector(t, root, nil)
		if code == 0 || strings.Contains(raw, "\t") || !strings.Contains(stderr, "symlink") {
			t.Fatalf("exit %d, stderr %q, listed %v", code, stderr, listedPaths(raw))
		}
	})
}

// A path filter grep cannot compile stops the scan; it does not empty the list
// and let a scan of nothing read as a reviewed repository.
func TestCollectorRefusesAFilterThatCannotRun(t *testing.T) {
	root := t.TempDir()
	writeFixtureTree(t, root)
	commitFixture(t, root)
	args := collectArgs(root)
	args[len(args)-1] = "(" // an ERE grep rejects
	cmd := exec.Command(args[0], args[1:]...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err == nil || strings.Contains(out.String(), "\t") {
		t.Fatalf("a filter that could not run must refuse; err=%v listed %v", err, listedPaths(out.String()))
	}
	if !strings.Contains(errb.String(), "path filter could not run") {
		t.Errorf("refusal does not say why: %q", errb.String())
	}
}

func TestCollectedSourceThatSaysNothingIsRefused(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("package ok"))
	for name, raw := range map[string]string{
		"empty output":         "",
		"no ignore-rules line": "src/ok.go\t" + enc + "\n",
		"no files":             collectModePrefix + "git\n",
		"only withheld files":  collectModePrefix + "git\n.npmrc\t" + enc + "\n",
	} {
		if err := parseCollected(raw).usable(); err == nil {
			t.Errorf("%s: a collection with nothing trustworthy to send was accepted", name)
		}
	}
	if err := parseCollected(collectModePrefix + "tree-gitignore\nsrc/ok.go\t" + enc + "\n").usable(); err != nil {
		t.Errorf("a real collection was refused: %v", err)
	}
}

// prompt builds the scan prompt from a collector run, as Scan does.
func prompt(raw string) string {
	return buildScanPrompt(parseCollected(raw).files, "{}")
}
