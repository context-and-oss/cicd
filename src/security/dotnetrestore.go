// The lockfile-free NuGet fallback: when a .NET tree commits no dependency
// graph Trivy can read, cicd restores one itself and scans that.
//
// Deliberately untagged (no //go:build !unit_test): script rendering, exit-status
// classification and message construction, none of which needs Dagger, so
// dotnetrestore_test.go drives all of it.
//
// Why this exists. ecosystems.go turns "the tree declares .NET and Trivy resolved
// no .NET graph" into a loud non-run, which is correct and, on its own,
// unhelpful: NuGet writes no lockfile unless a project opts in, so the remedy is
// a change in the *consumer's* repository and cicd has no lever on it. A gate a
// consumer cannot clear is a gate that gets switched off. Trivy reads
// packages.lock.json, `dotnet restore --use-lock-file` writes one, and the SDK
// that writes it is a container cicd already knows how to pin — so the graph is
// obtainable, it was simply never asked for.
//
// Measured end to end on testdata/dotnet-app-nolock (trivy 0.70.0, sdk 8.0): the
// restore covers both projects and the scan reports 85 NuGet components in an
// 87-component SBOM and two HIGH CVEs, with passed=true and an empty errors[].
// As committed that tree resolves no .NET graph at all — and being pure .NET, it
// reaches parseTrivyNative's `Results: null` error rather than a silent zero.
// The silent form of the same missing input needs a mixed tree, where another
// ecosystem's lockfile makes the report look normal (see the consumer case in
// specs/scan-nuget-without-a-lockfile.md). Same missing input, same remedy; only the loudness differs.
//
// Three properties are load-bearing, and each one is a way this could have
// become the false pass it exists to remove:
//
//  1. **The restore never manufactures a pass.** A restore that fails is an
//     error, not a fallback to silence — the caller lands on the same non-run it
//     would have had, plus the reason the restore failed.
//
//  2. **A partial restore is a failure.** A tree of twenty projects where one
//     fails to restore still ends up holding nineteen packages.lock.json files,
//     which is a resolvable input, which makes unresolvedEcosystems go
//     quiet — a green verdict over a project nothing looked at. So every project
//     is restored individually, each exit status is captured separately, and any
//     failure is reported by name. Restoring the tree in one command would have
//     collapsed all twenty statuses into one and made this undetectable.
//
//  3. **A restored graph is not a committed graph, and says so.** Versions are
//     resolved at scan time. Where a project pins exact versions the two are
//     identical; where it uses a floating range they can differ, so the scan can
//     describe packages the build will not use. That is a real limitation of the
//     fallback and the warning states it rather than letting a green tick imply
//     a guarantee the mechanism cannot make.
package main

import (
	"strconv"
	"strings"
)

// dotnetRestoreProjectPatterns are the project files worth restoring. The set
// matches the dotnet entry's markers in ecosystems.go minus its listings:
// a solution restores the projects it references, so restoring both would repeat
// the work while still missing a project no solution names.
var dotnetRestoreProjectPatterns = []string{"*.csproj", "*.fsproj", "*.vbproj"}

// dotnetRestorePaths are the fixed paths inside the restore container. Nothing
// consumer-supplied reaches them.
const (
	dotnetRestoreOutPath      = "/tmp/dotnet-restore.out"
	dotnetRestoreErrPath      = "/tmp/dotnet-restore.err"
	dotnetRestoreFailedPath   = "/tmp/dotnet-restore.failed"
	dotnetRestoreProjectsPath = "/tmp/dotnet-restore.projects"
	dotnetRestoreFindPath     = "/tmp/dotnet-restore.find"
)

// dotnetRestoreMount is where the source tree is mounted for the restore. It
// matches trivyConfigDir so the paths in a message name the same file the scan
// later reports a finding in.
const dotnetRestoreMount = trivyConfigDir

// dotnetRestoreNeeded reports the .NET marker files present in a tree that holds
// no dependency graph Trivy can read, or nil when the fallback has nothing to do.
//
// It asks the *same table* the verdict asks (depEcosystems), rather than a second
// list of filenames: a restore triggered by one set of rules and judged by
// another is how a tree gets restored and still reported unresolved, or worse,
// judged resolved on a lockfile the fallback never looked for.
//
// Trivy's resolved types are deliberately not consulted — they cannot be, the
// scan has not run yet. That is only ever wasteful, never wrong: an ecosystem
// Trivy would have resolved anyway (a committed node_modules, a
// Directory.Packages.props) gets a redundant restore whose output is a fuller
// graph than the one it would have had.
func dotnetRestoreNeeded(mount string, files []string) []string {
	for _, e := range depEcosystems() {
		if e.name != "dotnet" {
			continue
		}
		markers := matchDependencyFiles(mount, files, e.markers)
		if len(markers) == 0 || len(e.listingsOnly(mount, files)) > 0 {
			return nil
		}
		if len(matchDependencyFiles(mount, files, e.inputs)) > 0 {
			return nil
		}
		return markers
	}
	return nil
}

// dotnetRestoreScript renders the shell body of the restore.
//
// The project patterns are cicd constants — dotnetRestorePatternsAreShellSafe in
// the unit suite proves it — so single-quoting them is sound, and no consumer
// value is ever spliced into this body. Project *paths* are consumer-controlled
// and are therefore read from a file and passed as a quoted "$p", never
// interpolated: a path is an argument here, never shell source.
//
// Every status is written down instead of being collapsed into the script's own
// exit code. `find` gets its own file because a tree it could not walk means the
// project list is short for a reason nothing else would reveal, and each failed
// project is appended by name because "some project failed" is not something a
// consumer can act on. The script itself always exits 0; the classification
// happens in Go, where it can be tested.
//
// The last step snapshots the package metadata out of packages, the NuGet
// packages folder, inside this same exec — licencenuget.go carries why it must
// be this exec and not a later one.
func dotnetRestoreScript(mount, packages string) string {
	var expr []string
	for i, pattern := range dotnetRestoreProjectPatterns {
		if i > 0 {
			expr = append(expr, "-o")
		}
		expr = append(expr, "-name", "'"+pattern+"'")
	}
	return ": > " + dotnetRestoreOutPath + "\n" +
		": > " + dotnetRestoreErrPath + "\n" +
		": > " + dotnetRestoreFailedPath + "\n" +
		"find " + mount + " -type f \\( " + strings.Join(expr, " ") + " \\) " +
		"-not -path '*/bin/*' -not -path '*/obj/*' > " + dotnetRestoreProjectsPath +
		" 2>>" + dotnetRestoreErrPath + "\n" +
		"echo $? > " + dotnetRestoreFindPath + "\n" +
		"while IFS= read -r p; do\n" +
		"  [ -n \"$p\" ] || continue\n" +
		"  if ! dotnet restore \"$p\" --use-lock-file >>" + dotnetRestoreOutPath +
		" 2>>" + dotnetRestoreErrPath + "; then\n" +
		"    printf '%s\\n' \"$p\" >> " + dotnetRestoreFailedPath + "\n" +
		"  fi\n" +
		"done < " + dotnetRestoreProjectsPath + "\n" +
		nuspecSnapshotScript(packages) + "\n" +
		"exit 0"
}

// dotnetRestoreOutcome is what the restore container reports back, before any of
// it is turned into a verdict.
type dotnetRestoreOutcome struct {
	// Band and BandNote are the SDK the restore ran in and why that one.
	Band     string
	BandNote string
	// FindExit is `find`'s exit status as written by the script.
	FindExit string
	// Projects is every project file the script found, mount-relative.
	Projects []string
	// Failed is every project whose restore exited non-zero, mount-relative.
	Failed []string
	// Stderr is the combined stderr of the sweep and every restore.
	Stderr string
	// NuspecExit is the package-metadata snapshot's exit status. Only the
	// licence scan reads it; the dependency scan reads the lockfiles.
	NuspecExit string
}

// dotnetRestoreImageLabel names the SDK image a band restored in, for a message
// that has to say which SDK produced the graph.
func dotnetRestoreImageLabel(band string) string {
	return "mcr.microsoft.com/dotnet/sdk:" + band
}

// dotnetRestoreRunError classifies the restore, returning "" when every project
// the sweep found was restored.
//
// The three failures are kept apart because a consumer acts on them differently,
// and because collapsing them is how the middle one would disappear:
//
//   - `find` failed: the project list is unreliable, so "every project restored"
//     is a claim about an unknown set. Unknown fails.
//   - some project failed: the tree now holds lockfiles for the others, so
//     nothing downstream can tell that this project was never resolved. Only
//     this message can.
//   - no project found: every project the probe saw sits under bin/ or obj/.
//     A tree of solution files alone never gets here — dotnetRestoreNeeded
//     stands down on it. Restoring nothing and reporting success would hand
//     the caller a graph-free tree it believes was restored.
func dotnetRestoreRunError(out dotnetRestoreOutcome) string {
	const prefix = "security dependency scan: the .NET dependency-graph restore "

	if code := strings.TrimSpace(out.FindExit); code != "0" {
		msg := prefix + "could not list the project files"
		if code == "" {
			msg += " and recorded no exit status"
		} else {
			msg += " (find exited " + code + ")"
		}
		msg += ", so which projects needed restoring is unknown and a graph " +
			"restored for some of them cannot be told apart from a complete one"
		return appendStderr(msg, out.Stderr)
	}

	if len(out.Projects) == 0 {
		return prefix + "found no project file to restore under " +
			dotnetRestoreMount + " (looked for " +
			strings.Join(dotnetRestoreProjectPatterns, ", ") +
			", excluding bin/ and obj/), so no NuGet graph was produced and the " +
			"zero .NET vulnerabilities below are not a clean verdict"
	}

	if len(out.Failed) > 0 {
		msg := prefix + "failed for " + strconv.Itoa(len(out.Failed)) + " of " +
			strconv.Itoa(len(out.Projects)) + " project(s) in " +
			dotnetRestoreImageLabel(out.Band) + " (" +
			strings.Join(firstN(out.Failed, 3), ", ") + "). Those projects' " +
			"dependencies were not examined, and the lockfiles the other projects " +
			"produced hide that: the scan below reports findings for the projects " +
			"that restored and silence for these. Fix: commit packages.lock.json " +
			"for every project (<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>, " +
			"then `dotnet restore --use-lock-file`), or make the restore work here — " +
			"a private feed needs --nuget-feed-url and --nuget-token, and a target " +
			"framework outside cicd's pinned bands (" + dotnetBandsLabel() +
			") needs global.json to name one that is"
		return appendStderr(msg, out.Stderr)
	}

	return ""
}

// dotnetRestoreWarning is what a *successful* fallback says. It is a warning and
// not silence because a restored graph and a committed one are not the same
// evidence, and the difference is invisible in the findings.
//
// All three parts are load-bearing. It states that cicd resolved the graph
// rather than reading one, so nobody reads the finding list as describing a
// lockfile that exists. It names the drift a floating version range causes,
// because that is the one way this scan can be wrong about the artifact. And it
// gives the exact remedy, because a warning a consumer cannot act on is noise
// they learn to scroll past.
func dotnetRestoreWarning(out dotnetRestoreOutcome) string {
	return "security dependency scan: dotnet — no packages.lock.json, " +
		"packages.config or *.deps.json is committed, so cicd restored the NuGet " +
		"graph itself in " + dotnetRestoreImageLabel(out.Band) + " (" +
		strconv.Itoa(len(out.Projects)) + " project(s); " + out.BandNote +
		") and scanned that. The graph was resolved now, not when this artifact is " +
		"built: a project using a floating version range can build against package " +
		"versions this scan never saw. Committing a lockfile removes that gap and " +
		"skips the restore — set " +
		"<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in each " +
		"project (or a Directory.Build.props), run `dotnet restore --use-lock-file`, " +
		"and commit the generated packages.lock.json files."
}

// dotnetRestoreAttemptedNote is appended to the unresolved-ecosystem verdict when
// a restore was tried and did not put a graph in the tree. Without it that
// message reads as though cicd never tried, and the first thing a consumer does
// about it is exactly what cicd already did.
func dotnetRestoreAttemptedNote(band string) string {
	return "cicd also attempted to restore the graph itself in " +
		dotnetRestoreImageLabel(band) + " and that did not produce one either."
}

// appendStderr puts the first line of a tool's stderr on a message, when there
// is one. First line only: the rest is MSBuild's banner and notify renders each
// errors[] entry as a single markdown list item.
func appendStderr(msg, stderr string) string {
	if s := strings.TrimSpace(stderr); s != "" {
		return msg + ": " + firstLine(s)
	}
	return msg
}

// splitProbeLines turns a probe's stdout into mount-relative paths, dropping the
// blank line a trailing newline leaves behind.
func splitProbeLines(mount, raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, relativeToMount(mount, line))
		}
	}
	return out
}
