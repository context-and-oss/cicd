// Which files the Opengrep pass scans in a git checkout: the ones git would
// list, as Semgrep's did.
//
// Deliberately untagged, so gitscope_test.go drives the script text and every
// outcome; the container half is gitIgnoredScope in sast.go.
//
// Semgrep's image carried git, so in a checkout it scanned what `git ls-files`
// lists: tracked files and the untracked ones .gitignore does not exclude.
// Opengrep's base carries no git, and a .git in its mount is a scan that does
// not run, so the engine never sees one (withoutGitMetadata). Walking the
// tree it is then handed, it would scan a gitignored dist/, node_modules or
// generated client too — findings in files the repository does not contain,
// failing a gate that passed on the same commit the day before.
//
// cicd does not re-derive git's ignore rules: that would be a second resolver
// for a question git answers. git answers it, in the pinned gitleaks image,
// which already carries git for the history leg. Every path it reports as
// untracked and ignored is removed from the tree before Opengrep sees it.
//
// See specs/swap-semgrep-for-opengrep.md.
package main

import (
	"fmt"
	"strconv"
	"strings"
)

// gitScopeOut is where the script leaves its status and git's stderr.
const (
	gitScopeMount  = "/src"
	gitScopeOut    = "/tmp/gitscope"
	gitScopeStatus = gitScopeOut + "/status"
	gitScopeErr    = gitScopeOut + "/err"
)

// gitScopeScript asks git which untracked files and directories its ignore
// rules exclude, and removes each one from the copy of the tree. The list is
// NUL-separated and reaches rm as arguments after "--", never as shell
// source, so no path can be read as an option or a command. It always exits
// 0 and writes one status line:
//
//	none                            the tree has no .git; nothing to ask
//	git <exit> <ignored> <rm exit>  git's answer, how many paths, and rm's exit
//
// <ignored> and <rm exit> are "-" when git did not answer.
func gitScopeScript() string {
	return "cd " + gitScopeMount + "\n" +
		"mkdir -p " + gitScopeOut + "\n" +
		": > " + gitScopeErr + "\n" +
		"if [ ! -e .git ]; then echo none > " + gitScopeStatus + "; exit 0; fi\n" +
		"git -c safe.directory='*' ls-files -z --others --ignored --exclude-standard --directory " +
		"> " + gitScopeOut + "/ignored 2> " + gitScopeErr + "\n" +
		"code=$?\n" +
		"if [ \"$code\" -ne 0 ]; then echo \"git $code - -\" > " + gitScopeStatus + "; exit 0; fi\n" +
		"n=$(tr -cd '\\000' < " + gitScopeOut + "/ignored | wc -c | tr -d ' ')\n" +
		"xargs -0 -r rm -rf -- < " + gitScopeOut + "/ignored 2>> " + gitScopeErr + "\n" +
		"echo \"git 0 $n $?\" > " + gitScopeStatus + "\n" +
		"exit 0\n"
}

// gitScope is what the Opengrep pass does with the script's answer.
type gitScope struct {
	// Pruned is true when the tree the script left is the one to scan: git
	// answered, whether or not every removal succeeded.
	Pruned bool
	// Warning names a scope that differs from git's, or what was left out.
	// Empty when there was nothing to say.
	Warning string
}

// classifyGitScope reads the script's status line. It never fails the scan:
// every outcome is a scope Opengrep can still run on, and each one that is not
// git's own answer is named.
func classifyGitScope(status, stderr string) gitScope {
	f := strings.Fields(status)
	if len(f) == 1 && f[0] == "none" {
		return gitScope{}
	}
	walked := " — the scan walked every file in the tree, gitignored ones included"
	if len(f) != 4 || f[0] != "git" {
		return gitScope{Warning: fmt.Sprintf("opengrep: could not read which files .gitignore excludes "+
			"(unexpected status %q)%s", strings.TrimSpace(status), walked)}
	}
	if f[1] != "0" {
		why := "git exited " + f[1]
		if s := lastNonEmptyLine(stderr); s != "" {
			why += ": " + s
		}
		return gitScope{Warning: "opengrep: could not ask git which files .gitignore excludes (" + why + ")" + walked}
	}
	n, err := strconv.Atoi(f[2])
	if err != nil {
		return gitScope{Warning: fmt.Sprintf("opengrep: could not read how many paths .gitignore excludes "+
			"(%q)%s", f[2], walked)}
	}
	if f[3] != "0" {
		why := "rm exited " + f[3]
		if s := lastNonEmptyLine(stderr); s != "" {
			why += ": " + s
		}
		return gitScope{Pruned: true, Warning: fmt.Sprintf("opengrep: could not remove every one of the %d "+
			"gitignored %s before scanning (%s), so some may have been scanned", n, pick(n, "path", "paths"), why)}
	}
	if n == 0 {
		return gitScope{Pruned: true}
	}
	return gitScope{Pruned: true, Warning: fmt.Sprintf("opengrep: %d gitignored %s present in the tree "+
		"%s not scanned, as `git ls-files` would not list %s", n, pick(n, "path", "paths"),
		pick(n, "was", "were"), pick(n, "it", "them"))}
}
