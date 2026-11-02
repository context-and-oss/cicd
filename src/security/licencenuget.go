// NuGet licences, and what a licence scan that read nothing says.
//
// Deliberately untagged: path and message construction only, so
// licencenuget_test.go reaches it under `go test -tags unit_test`.
//
// Why the licence scan restores. Trivy reads a NuGet package's licence from its
// .nuspec in the global packages folder, never from packages.lock.json: the
// lockfile names versions, not licences. Measured on MediatR with the pinned
// Trivy, the restored lockfiles alone gave 0 licence declarations; the same tree
// with the restored packages folder mounted gave 277, and a snapshot holding only
// the .nuspec files gave the identical 277. So a .NET tree reads 0 NuGet licences
// whether or not it commits a lockfile, and the restore is what clears it — for
// every .NET tree, not only the lockfile-free ones the dependency scan restores.
//
// Why a snapshot and not the cache volume. The packages folder is a shared cache
// volume, and a cache volume is not part of an exec's cached result: an engine
// that pruned it while keeping the restore exec cached would hand the licence
// scan an empty folder, and 0 licences would read exactly like a tree whose
// packages declare none. Copying the .nuspec files out *inside the restore exec*
// makes them part of that exec's output layer, cached together with the
// lockfiles the same exec wrote, so the two cannot fall out of step.
package main

import (
	"path"
	"strconv"
	"strings"
)

// Paths inside the restore container. Constants, never consumer values.
const (
	// nuspecSnapshotPath receives every .nuspec in the packages folder, in the
	// folder's own <id>/<version>/<id>.nuspec layout, which is the layout Trivy
	// looks a package up by.
	nuspecSnapshotPath = "/tmp/nuspecs"
	// dotnetRestoreNuspecPath is the snapshot's exit status: 0, or 1 when any
	// directory or copy failed.
	dotnetRestoreNuspecPath = "/tmp/dotnet-restore.nuspec"
)

// nuspecSnapshotScript copies the .nuspec files out of the packages folder.
//
// It runs in a subshell so its `cd` cannot move the restore script, and the
// glob is guarded with `[ -f ]` because an unmatched POSIX glob is the literal
// pattern, not an empty list. A package folder cicd could not copy is recorded,
// not skipped: a licence missing for that reason must not look like a package
// that declares none.
//
// The snapshot holds every package in the shared cache, not only this tree's.
// Trivy looks packages up by the id and version the lockfile names, so a
// neighbour's package is never read; it costs bytes, not correctness, and it is
// inside the same trust boundary as the restore that shares that cache.
func nuspecSnapshotScript(packages string) string {
	return "(\n" +
		"  rc=0\n" +
		"  mkdir -p " + nuspecSnapshotPath + " || rc=1\n" +
		"  if [ -d " + packages + " ]; then\n" +
		"    if cd " + packages + "; then\n" +
		"      for f in */*/*.nuspec; do\n" +
		"        [ -f \"$f\" ] || continue\n" +
		"        mkdir -p \"" + nuspecSnapshotPath + "/${f%/*}\" && cp \"$f\" \"" + nuspecSnapshotPath + "/$f\" || rc=1\n" +
		"      done\n" +
		"    else\n" +
		"      rc=1\n" +
		"    fi\n" +
		"  fi\n" +
		"  echo $rc > " + dotnetRestoreNuspecPath + "\n" +
		")"
}

// dotnetLicenceRestoreNeeded reports the .NET marker files in a tree, or nil.
//
// Unlike dotnetRestoreNeeded it does not stand down when a lockfile is
// committed: a committed packages.lock.json still carries no licence, so every
// .NET tree needs the packages folder the restore fills. It asks the same table
// the dependency verdict asks, so the two cannot disagree about what is .NET.
//
// A tree of solution files and no project stands it down too: there is
// nothing to restore, and dotnetSolutionsWithoutProjectsWarning says so.
func dotnetLicenceRestoreNeeded(mount string, files []string) []string {
	for _, e := range depEcosystems() {
		if e.name == "dotnet" {
			if len(e.listingsOnly(mount, files)) > 0 {
				return nil
			}
			return matchDependencyFiles(mount, files, e.markers)
		}
	}
	return nil
}

// dotnetSolutionsWithoutProjectsWarning is what both dependency rows say about
// a tree whose only .NET files are solutions, row naming the row it opens.
//
// It is a warning and not an error because the consumer has nothing to clear:
// no project means no NuGet graph exists, so a restore has no input and a
// lockfile has no project to belong to. A solution checked in as a fixture or a
// build entry point is a normal tree, and failing it would get the scan
// switched off. It is not silence either, because a solution can list a
// project of a type cicd does not restore, and that project's packages are
// then read only from a lockfile committed beside it.
func dotnetSolutionsWithoutProjectsWarning(row string, solutions []string) string {
	return row + ": SOLUTION WITHOUT PROJECTS — " + strconv.Itoa(len(solutions)) +
		" solution file(s) (" + strings.Join(firstN(solutions, 3), ", ") + ") and no " +
		strings.Join(dotnetRestoreProjectPatterns, ", ") + " anywhere in the scanned tree, so " +
		"no NuGet dependency graph exists to restore and none was restored. A project of " +
		"another type a solution can list (.sqlproj, .esproj, .proj) is not restored by cicd: " +
		"its NuGet packages are judged only from a packages.lock.json committed beside it."
}

// dotnetLicenceRestoreError classifies a restore for the licence scan, "" when
// every project restored and the snapshot was taken.
//
// It does not reuse dotnetRestoreRunError's text. That message speaks about
// vulnerabilities and prescribes committing a lockfile, and a lockfile does not
// clear this one: the licence lives in the package, so the only remedy is a
// restore that works here.
func dotnetLicenceRestoreError(out dotnetRestoreOutcome) string {
	const prefix = "security license scan: the .NET restore the NuGet licences are read from "

	if code := strings.TrimSpace(out.FindExit); code != "0" {
		msg := prefix + "could not list the project files"
		if code == "" {
			msg += " and recorded no exit status"
		} else {
			msg += " (find exited " + code + ")"
		}
		msg += ", so which NuGet packages this tree depends on is unknown and their licences were not read"
		return appendStderr(msg, out.Stderr)
	}

	if len(out.Projects) == 0 {
		return prefix + "found no project file under " + dotnetRestoreMount + " (looked for " +
			strings.Join(dotnetRestoreProjectPatterns, ", ") + ", excluding bin/ and obj/), " +
			"so no NuGet package metadata exists and no NuGet licence was read"
	}

	if len(out.Failed) > 0 {
		msg := prefix + "failed for " + strconv.Itoa(len(out.Failed)) + " of " +
			strconv.Itoa(len(out.Projects)) + " project(s) in " + dotnetRestoreImageLabel(out.Band) +
			" (" + strings.Join(firstN(out.Failed, 3), ", ") + "). Those projects' NuGet licences " +
			"were not read, and the licences read for the others hide that. Committing a lockfile " +
			"does not clear this — a lockfile names versions, not licences. Fix: make the restore " +
			"work here — a private feed needs --nuget-feed-url and --nuget-token, and a target " +
			"framework outside cicd's pinned bands (" + dotnetBandsLabel() + ") needs global.json " +
			"to name one that is; a project that restores under no SDK (the NuGet error below names " +
			"it, e.g. NU1201 for a ProjectReference to a framework it cannot consume) is a defect " +
			"in the tree, fixed in its TargetFramework or ProjectReference"
		return appendStderr(msg, out.Stderr)
	}

	if code := strings.TrimSpace(out.NuspecExit); code != "0" {
		msg := prefix + "restored every project but could not copy the package metadata out of " +
			"the NuGet packages folder"
		if code == "" {
			msg += " (no exit status recorded)"
		}
		return msg + ", so which NuGet licences the tree carries is unknown"
	}

	return ""
}

// dotnetLicenceRestoreWarning says the NuGet licences come from a graph cicd
// resolved, and how much of that graph the scan then read.
//
// Restored is not read. The restore sweeps every project under the mount before
// Trivy runs; Trivy then honours the tree's own trivy.yaml skips, and
// --license-exclude drops what its patterns cover. On this repository eight
// fixture projects restored and none was read, because trivy.yaml skips the
// directory that holds them, and the old message still said the restore was so
// Trivy could read their licences. Asking trivy.yaml up front would be a second
// reader of that file, so Trivy's own report is asked afterwards: a project was
// read when the report lists a NuGet lockfile in its directory with at least one
// dependency package. That is the lockfile read, not the licences: how many of
// those packages carry one is licenceCoverageWarning's line. A project that sets
// NuGetLockFilePath elsewhere reads as unlisted — the message says what it could
// not see rather than guessing.
//
// cov is nil when the scan did not complete; the warning then says what was
// restored and claims nothing about what was read.
func dotnetLicenceRestoreWarning(out dotnetRestoreOutcome, cov *licenceCoverage, ex *licenseExcluder) string {
	msg := "security license scan: dotnet — cicd restored the NuGet graph in " +
		dotnetRestoreImageLabel(out.Band) + " (" + strconv.Itoa(len(out.Projects)) +
		" project(s); " + out.BandNote + ") so Trivy could read each package's licence from " +
		"its .nuspec."
	if cov == nil {
		return msg + " The scan did not complete, so how many of those projects it read is unknown."
	}
	read, excluded, unlisted := dotnetRestoreReadSplit(out.Projects, *cov, ex)
	switch read {
	case 0:
		msg += " Trivy listed the NuGet packages of none of them"
	case len(out.Projects):
		msg += " Trivy listed the NuGet packages of all of them"
	default:
		msg += " Trivy listed the NuGet packages of " + strconv.Itoa(read) + " of them"
	}
	if len(excluded) > 0 {
		msg += "; --license-exclude removed " + strconv.Itoa(len(excluded)) + " (" +
			strings.Join(firstN(excluded, 3), ", ") + moreSuffix(len(excluded), 3) + ")"
	}
	if len(unlisted) > 0 {
		msg += "; it listed no NuGet package for " + strconv.Itoa(len(unlisted)) + " (" +
			strings.Join(firstN(unlisted, 3), ", ") + moreSuffix(len(unlisted), 3) + "), " +
			"which a project with no PackageReference explains and a skip-dirs or skip-files " +
			"in the tree's trivy.yaml also produces — those projects' licences were not judged"
	}
	msg += "."
	if read > 0 {
		msg += " Whether a listed package carries a licence is the dependency coverage " +
			"line's to say. The graph was resolved now: a project using a floating version " +
			"range can build against package versions whose licences this scan never saw."
	}
	return msg
}

// dotnetRestoreReadSplit sorts the restored projects into those whose NuGet
// lockfile Trivy listed packages for, those a --license-exclude pattern covers,
// and the rest. A lockfile is matched by directory, not by name, so NuGet's
// per-project lockfile name in a folder holding several projects still matches.
// covers, not match: a pattern that covered only a restored project has removed
// no declaration and must stay reported as inert.
func dotnetRestoreReadSplit(projects []string, cov licenceCoverage, ex *licenseExcluder) (read int, excluded, unlisted []string) {
	listed := map[string]bool{}
	for _, e := range cov.Ecosystems {
		if e.Type != "nuget" {
			continue
		}
		for _, t := range e.Targets {
			listed[path.Dir(cleanRelPath(t))] = true
		}
	}
	for _, p := range projects {
		dir := path.Dir(cleanRelPath(p))
		switch {
		case listed[dir]:
			read++
		case ex.covers(path.Join(dir, "packages.lock.json")):
			excluded = append(excluded, p)
		default:
			unlisted = append(unlisted, p)
		}
	}
	return read, excluded, unlisted
}

// cleanRelPath puts a mount-relative path and a Trivy target in one form.
func cleanRelPath(p string) string {
	return strings.TrimPrefix(path.Clean(strings.TrimSpace(p)), "./")
}

// licenceScanMode is which input a licence scan read, for the zero-read message.
type licenceScanMode int

const (
	licenceScanTree licenceScanMode = iota
	licenceScanSourceOnly
	licenceScanSBOM
)

// licenceZeroRead reports whether a licence row read nothing at all, and is
// therefore SKIPPED rather than CLEAN.
//
// "0 outside policy" over zero declarations is a policy that judged nothing,
// and CLEAN is the word for a policy that judged something and found it
// acceptable. SKIPPED still passes — a tree whose packages carry no licence
// metadata Trivy can reach is not a gate the consumer can clear by changing
// their code — but it no longer claims a judgement.
//
// A run that excluded every declaration is not a zero read: it read them and the
// consumer's own patterns removed them, which the exclusion warning already
// reports. A run that did not complete is never a zero read either; it is an
// error, and SKIPPED must not be able to hide one.
func licenceZeroRead(ran bool, scanned, excluded int) bool {
	return ran && scanned == 0 && excluded == 0
}

// licenceZeroReadWarning names what a zero-read licence scan was looking at.
// When dependency inputs exist, it names them: a lockfile that yielded no
// licence is the case a reader would otherwise mistake for a clean tree.
func licenceZeroReadWarning(mode licenceScanMode, inputs []string) string {
	const tail = " Nothing was judged, so this row is SKIPPED rather than CLEAN."
	switch mode {
	case licenceScanSBOM:
		return "Licences: NOT READ — the supplied SBOM carries no licence declaration." + tail +
			" Absent licence metadata is not proof of licence compliance."
	case licenceScanSourceOnly:
		return "Licences: NOTHING IN SCOPE — the tree's own files carry no licence declaration " +
			"Trivy recognises." + tail
	}
	if len(inputs) == 0 {
		return "Licences: NOTHING IN SCOPE — no dependency manifest or lockfile, and no licence " +
			"declaration in the tree's own files." + tail
	}
	return "Licences: NOT READ — " + strconv.Itoa(len(inputs)) + " dependency input(s) are present (" +
		strings.Join(firstN(inputs, 3), ", ") + moreSuffix(len(inputs), 3) + ") and 0 licence " +
		"declarations were read from them or from the tree's own files." + tail +
		" A lockfile names package versions, not licences: Trivy reads a dependency's licence " +
		"from installed package metadata, which cicd supplies only for .NET (by restoring the " +
		"NuGet graph) and Go (by downloading the module graph from the Go module proxy), so these " +
		"dependencies' licences were not judged by this run."
}

// moreSuffix is ", …" when a list was cut to n, so a reader can tell a sample
// from the whole.
func moreSuffix(total, n int) string {
	if total > n {
		return ", …"
	}
	return ""
}
