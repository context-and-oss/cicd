// Go licences: which modules to download, and what the download did.
//
// Deliberately untagged: parsing, planning and message construction only, so
// licencegomod_test.go reaches it under `go test -tags unit_test`. The container
// half is goexec.go.
//
// Why the licence scan downloads. Trivy reads a Go module's licence from the
// module's own files in the module cache ($GOPATH/pkg/mod), never from go.mod or
// go.sum: those name versions, not licences. Measured with the pinned Trivy on a
// module requiring 36 others: 0 of 36 carried a licence with no module cache, 36
// of 36 with one, and 36 of 36 — the identical licences — with a snapshot holding
// only the top-level regular files of each module directory (about 20 MB against
// 309 MB for the whole cache).
//
// Why the Go module proxy and nothing else. GOPROXY is proxy.golang.org with no
// `direct` fallback, so the go command never contacts a host a go.mod names: a
// module path is a URL, and with `direct` a consumer's go.mod could point this
// container at any host. A module the proxy does not serve — every private module
// — fails with the proxy's own 404 or 410, one result per module, and is named as
// not downloaded rather than retried somewhere else. The quality module's Go test
// leg already sends the same module paths to the same proxy, so this adds no new
// party that learns a private module's name.
//
// Why a snapshot and not the cache volume. Same reason as the NuGet snapshot in
// licencenuget.go: a cache volume is not part of an exec's cached result, so the
// files Trivy reads are copied out inside the download exec, into its output
// layer, where a pruned volume cannot empty them behind a cached exec.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Paths and settings inside the download container. Constants, never consumer
// values.
const (
	// goSrcMount is where the tree is mounted for go mod edit.
	goSrcMount = "/cicd/gosrc"
	// goWorkDir is an empty working directory: go mod download runs outside any
	// module, so no go.mod, go.work or toolchain line of the consumer's applies.
	goWorkDir = "/cicd/gowork"
	// goModCachePath and goModCacheVolume are the module cache, kept across runs
	// the way nugetPackagesVolume is. Module content is verified against go.sum
	// data from the checksum database before it lands, so a cached module is the
	// module the proxy served.
	goModCachePath   = "/cicd/gomodcache"
	goModCacheVolume = "cicd-go-mod"
	// goSnapshotPath is a GOPATH root holding pkg/mod/<module>@<version> with
	// each module's top-level files, the layout Trivy looks a module up by.
	goSnapshotPath = "/cicd/gosnap"
	// trivyGopathMount is where the snapshot is mounted for Trivy, which reads
	// $GOPATH/pkg/mod.
	trivyGopathMount = "/cicd/gopath"
	// goModuleProxy is the only source a module is downloaded from.
	goModuleProxy = "https://proxy.golang.org"
	// goDownloadBatch is how many modules one go mod download invocation gets.
	goDownloadBatch = "100"

	goEditOutPath      = "/cicd/gomod/edit.out"
	goEditDonePath     = "/cicd/gomod/edit.done"
	goDownloadArgsPath = "/cicd/gomod/download.args"
	goDownloadRelsPath = "/cicd/gomod/download.rels"
	goDownloadOutPath  = "/cicd/gomod/download.json"
	goDownloadErrPath  = "/cicd/gomod/download.err"
	goDownloadExitPath = "/cicd/gomod/download.exit"
	goCopiedPath       = "/cicd/gomod/copied"
	goCopyFailedPath   = "/cicd/gomod/copyfailed"
	goDownloadDonePath = "/cicd/gomod/download.done"

	goEditMarker    = "#cicd-gomod-edit "
	goEditErrMarker = "#cicd-gomod-err "
)

// goLicenceDownloadNeeded reports the go.mod files in a tree, or nil. It asks the
// same table the dependency verdict asks, so the two cannot disagree about what
// is Go.
func goLicenceDownloadNeeded(mount string, files []string) []string {
	for _, e := range depEcosystems() {
		if e.name == "go" {
			return matchDependencyFiles(mount, files, e.markers)
		}
	}
	return nil
}

// goModEditScript reads every go.mod named in "$@" with go mod edit -json and
// writes one section per file to goEditOutPath: a `#cicd-gomod-edit <i> <rc>`
// line, then the JSON on success or the stderr lines, each prefixed, on failure.
// The go.mod paths arrive as arguments, never as script text. A JSON document
// never holds a raw newline inside a string, so no line of it can start with the
// marker.
func goModEditScript() string {
	return "mkdir -p /cicd/gomod || exit 1\n" +
		": > " + goEditOutPath + "\n" +
		"i=0\n" +
		"for f in \"$@\"; do\n" +
		"  go mod edit -json \"$f\" > /cicd/gomod/one.json 2> /cicd/gomod/one.err\n" +
		"  rc=$?\n" +
		"  echo \"" + goEditMarker + "$i $rc\" >> " + goEditOutPath + "\n" +
		"  if [ \"$rc\" -eq 0 ]; then\n" +
		"    cat /cicd/gomod/one.json >> " + goEditOutPath + "\n" +
		"    echo >> " + goEditOutPath + "\n" +
		"  else\n" +
		"    head -c 2000 /cicd/gomod/one.err | sed 's/^/" + goEditErrMarker + "/' >> " + goEditOutPath + "\n" +
		"    echo >> " + goEditOutPath + "\n" +
		"  fi\n" +
		"  i=$((i+1))\n" +
		"done\n" +
		"echo 0 > " + goEditDonePath + "\n" +
		"exit 0"
}

// goDownloadScript downloads every module listed in goDownloadArgsPath and copies
// the top-level files of each directory named in goDownloadRelsPath into the
// snapshot. It always exits 0 and writes each status down; goexec.go reads them
// back and classifyGoDownload decides. A module directory the download did not
// produce is left out of both lists, so classification can tell "never
// downloaded" from "downloaded and could not be copied".
func goDownloadScript() string {
	return "xargs -n " + goDownloadBatch + " go mod download -json < " + goDownloadArgsPath +
		" > " + goDownloadOutPath + " 2> " + goDownloadErrPath + "\n" +
		"echo $? > " + goDownloadExitPath + "\n" +
		": > " + goCopiedPath + "\n" +
		": > " + goCopyFailedPath + "\n" +
		"mkdir -p " + goSnapshotPath + "/pkg/mod\n" +
		"while IFS= read -r rel; do\n" +
		"  [ -n \"$rel\" ] || continue\n" +
		"  src=\"" + goModCachePath + "/$rel\"\n" +
		"  [ -d \"$src\" ] || continue\n" +
		"  dst=\"" + goSnapshotPath + "/pkg/mod/$rel\"\n" +
		"  ok=0\n" +
		"  mkdir -p \"$dst\" || ok=1\n" +
		"  for f in \"$src\"/*; do\n" +
		"    [ -f \"$f\" ] || continue\n" +
		"    cp \"$f\" \"$dst/\" || ok=1\n" +
		"  done\n" +
		"  if [ \"$ok\" -eq 0 ]; then echo \"$rel\" >> " + goCopiedPath + "; else echo \"$rel\" >> " + goCopyFailedPath + "; fi\n" +
		"done < " + goDownloadRelsPath + "\n" +
		"echo 0 > " + goDownloadDonePath + "\n" +
		"exit 0"
}

// goModVersion is a module path and version as go mod edit -json prints them.
type goModVersion struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

// goModEdit is the slice of go mod edit -json this file reads.
type goModEdit struct {
	Require []struct {
		Path     string `json:"Path"`
		Version  string `json:"Version"`
		Indirect bool   `json:"Indirect"`
	} `json:"Require"`
	Replace []struct {
		Old goModVersion `json:"Old"`
		New goModVersion `json:"New"`
	} `json:"Replace"`
}

// goModRef is one module version to download.
type goModRef struct {
	Path    string
	Version string
}

func (r goModRef) String() string { return r.Path + "@" + r.Version }

// goDownloadPlan is what the go.mod files ask for.
type goDownloadPlan struct {
	// GoMods is every go.mod read, mount-relative, in the order given.
	GoMods []string
	// Refs is every module version to download, deduplicated and sorted.
	Refs []goModRef
	// RequiredBy is the go.mod files that require each ref, for attribution.
	RequiredBy map[goModRef][]string
	// Local is the requirements replaced by a directory in the tree. Nothing is
	// downloaded for them, and Trivy reads no licence for them from a module
	// cache.
	Local []string
	// Rejected is the requirements that are not a module reference cicd hands
	// to the go command.
	Rejected []string
	// Errors is every go.mod go mod edit could not read. Each one is a non-run:
	// Trivy may list nothing for a go.mod it cannot parse, so the coverage line
	// could not show the gap.
	Errors []string
}

// goEditSection is one go.mod's section of the go mod edit stream.
type goEditSection struct {
	rc     string
	body   strings.Builder
	stderr []string
}

// parseGoModEditStream splits goModEditScript's output into one section per
// go.mod index. A section that never appears is absent from the map.
func parseGoModEditStream(raw string) map[int]*goEditSection {
	out := map[int]*goEditSection{}
	var cur *goEditSection
	for _, line := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(line, goEditMarker):
			cur = nil
			fields := strings.Fields(strings.TrimPrefix(line, goEditMarker))
			if len(fields) != 2 {
				continue
			}
			i, err := strconv.Atoi(fields[0])
			if err != nil || i < 0 {
				continue
			}
			cur = &goEditSection{rc: fields[1]}
			out[i] = cur
		case cur == nil:
		case strings.HasPrefix(line, goEditErrMarker):
			cur.stderr = append(cur.stderr, strings.TrimPrefix(line, goEditErrMarker))
		default:
			cur.body.WriteString(line)
			cur.body.WriteByte('\n')
		}
	}
	return out
}

// planGoDownload turns the go mod edit stream for gomods into the modules to
// download, applying each go.mod's replace directives the way the go command
// does: a replace naming the required version wins over one naming none.
func planGoDownload(gomods []string, stream string) goDownloadPlan {
	plan := goDownloadPlan{GoMods: gomods, RequiredBy: map[goModRef][]string{}}
	sections := parseGoModEditStream(stream)
	for i, gm := range gomods {
		sec := sections[i]
		if sec == nil {
			plan.Errors = append(plan.Errors, "security license scan: go mod edit left no result for "+gm+
				", so which modules it requires is unknown and their licences were not read")
			continue
		}
		if sec.rc != "0" {
			msg := "security license scan: go mod edit could not read " + gm + " (exit " + sec.rc + ")"
			if len(sec.stderr) > 0 {
				msg += ": " + strings.TrimSpace(sec.stderr[0])
			}
			plan.Errors = append(plan.Errors, msg+". Trivy may list no module for a go.mod it cannot "+
				"parse, so the licences it requires were not read and the dependency coverage line "+
				"cannot show it. Fix the go.mod; if the tree's trivy.yaml skips its directory, "+
				"--license-exclude the same path so cicd does not read it either")
			continue
		}
		var doc goModEdit
		if err := json.Unmarshal([]byte(sec.body.String()), &doc); err != nil {
			plan.Errors = append(plan.Errors, "security license scan: could not parse go mod edit's "+
				"output for "+gm+", so which modules it requires is unknown: "+err.Error())
			continue
		}
		for _, req := range doc.Require {
			ref := goModRef{Path: req.Path, Version: req.Version}
			if to, ok := goReplacement(doc, ref); ok {
				if to.Version == "" {
					plan.Local = append(plan.Local, ref.String()+" => "+to.Path+" ("+gm+")")
					continue
				}
				ref = goModRef(to)
			}
			if why := goModRefRejected(ref); why != "" {
				plan.Rejected = append(plan.Rejected, strconv.Quote(ref.String())+" ("+gm+": "+why+")")
				continue
			}
			if _, seen := plan.RequiredBy[ref]; !seen {
				plan.Refs = append(plan.Refs, ref)
			}
			plan.RequiredBy[ref] = append(plan.RequiredBy[ref], gm)
		}
	}
	sort.Slice(plan.Refs, func(i, j int) bool { return plan.Refs[i].String() < plan.Refs[j].String() })
	sort.Strings(plan.Local)
	sort.Strings(plan.Rejected)
	return plan
}

// goReplacement reports the replace directive that applies to ref, if any.
func goReplacement(doc goModEdit, ref goModRef) (goModVersion, bool) {
	var wildcard *goModVersion
	for i := range doc.Replace {
		r := doc.Replace[i]
		if r.Old.Path != ref.Path {
			continue
		}
		if r.Old.Version == ref.Version {
			return r.New, true
		}
		if r.Old.Version == "" {
			wildcard = &doc.Replace[i].New
		}
	}
	if wildcard != nil {
		return *wildcard, true
	}
	return goModVersion{}, false
}

var (
	goModPathChars = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+$`)
	// goModVersionForm is a canonical semantic version, pseudo-versions and
	// +incompatible included. The go command reports a download under the
	// canonical version, so a non-canonical one would never match its result.
	goModVersionForm = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// goModRefRejected says why ref is not handed to the go command, or "".
//
// The ref becomes an argument to go mod download, so it is held to a strict
// form first: a leading "-" would be read as a flag, and whitespace or a quote
// would split it under xargs. A path with no dot in its first element is not one
// the Go module proxy serves.
func goModRefRejected(ref goModRef) string {
	p := ref.Path
	switch {
	case p == "" || !goModPathChars.MatchString(p):
		return "not a module path"
	case strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/"):
		return "not a module path"
	case !goModVersionForm.MatchString(ref.Version):
		return "not a canonical module version"
	}
	elems := strings.Split(p, "/")
	for _, e := range elems {
		if e == "" || e == "." || e == ".." {
			return "not a module path"
		}
	}
	if !strings.Contains(elems[0], ".") {
		return "no dot in the first path element, so not a module the Go module proxy serves"
	}
	return ""
}

// goEscapePath is the module cache's case encoding: each upper-case letter
// becomes "!" and its lower-case form, so a cache on a case-insensitive file
// system cannot merge two modules.
func goEscapePath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// goCacheRel is ref's directory under the module cache root.
func goCacheRel(ref goModRef) string {
	return goEscapePath(ref.Path) + "@" + goEscapePath(ref.Version)
}

// goDownloadArgs and goDownloadRels are the data files the download script reads.
func goDownloadArgs(refs []goModRef) string {
	var b strings.Builder
	for _, r := range refs {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func goDownloadRels(refs []goModRef) string {
	var b strings.Builder
	for _, r := range refs {
		b.WriteString(goCacheRel(r))
		b.WriteByte('\n')
	}
	return b.String()
}

// goDownloadRun is what the download exec wrote down.
type goDownloadRun struct {
	Exit       string
	JSON       string
	Stderr     string
	Copied     string
	CopyFailed string
}

// goDownloadOutcome is the plan and what happened to each module in it.
type goDownloadOutcome struct {
	Plan       goDownloadPlan
	Downloaded int
	// NotServed is the modules the Go module proxy answered 404 or 410 for,
	// which is what a private module looks like from outside.
	NotServed []string
	// Failed is every other module that did not download, with the go
	// command's own first line.
	Failed []string
	// Errors is what makes the download's own result unknown: no result for a
	// module, a result cicd cannot place, a copy that failed. Each is a non-run.
	Errors []string
}

// goDownloadResult is one object of go mod download -json.
type goDownloadResult struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
	Error   string `json:"Error"`
}

// classifyGoDownload sorts every planned module into downloaded, not served,
// failed, or unknown.
//
// A module that did not download is a warning, not an error: there is no Go
// credential input, so the consumer cannot clear it, and the coverage line
// already makes the row PARTLY READ or SKIPPED. What is an error is a download
// whose own outcome cicd cannot state — a module with no result at all, a
// result in a directory cicd did not expect, or files it could not copy —
// because then the licences read are a subset nobody can see the edge of.
func classifyGoDownload(plan goDownloadPlan, run goDownloadRun) goDownloadOutcome {
	out := goDownloadOutcome{Plan: plan}
	const prefix = "security license scan: the Go module download the Go licences are read from "

	exit := strings.TrimSpace(run.Exit)
	// xargs exits 0 when every go mod download succeeded and 123 when any
	// exited 1–125; anything else is xargs or the go command not running.
	if exit != "0" && exit != "123" {
		msg := prefix + "did not run"
		if exit == "" {
			msg += " and recorded no exit status"
		} else {
			msg += " (xargs exited " + exit + ")"
		}
		out.Errors = append(out.Errors, appendStderr(msg+", so no Go module licence was read", run.Stderr))
		return out
	}

	results := map[goModRef]goDownloadResult{}
	dec := json.NewDecoder(strings.NewReader(run.JSON))
	for {
		var r goDownloadResult
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			out.Errors = append(out.Errors, prefix+"wrote output cicd could not parse ("+err.Error()+
				"), so which modules downloaded is unknown")
			return out
		}
		results[goModRef{Path: r.Path, Version: r.Version}] = r
	}
	copied := lineSet(run.Copied)
	copyFailed := lineSet(run.CopyFailed)

	var missing, misplaced, uncopied []string
	for _, ref := range plan.Refs {
		label := goRefLabel(ref, plan.RequiredBy[ref])
		r, ok := results[ref]
		switch {
		case !ok:
			missing = append(missing, label)
		case r.Error != "":
			if goNotServed(r.Error) {
				out.NotServed = append(out.NotServed, label)
			} else {
				out.Failed = append(out.Failed, label+": "+boundedLine(r.Error, 200))
			}
		case path.Clean(r.Dir) != goModCachePath+"/"+goCacheRel(ref):
			misplaced = append(misplaced, label+" in "+strconv.Quote(r.Dir))
		case copyFailed[goCacheRel(ref)]:
			uncopied = append(uncopied, label)
		case !copied[goCacheRel(ref)]:
			uncopied = append(uncopied, label+" (not in the module cache)")
		default:
			out.Downloaded++
		}
	}
	if len(missing) > 0 {
		out.Errors = append(out.Errors, appendStderr(prefix+"returned no result for "+
			strconv.Itoa(len(missing))+" module(s) ("+strings.Join(firstN(missing, 3), ", ")+
			moreSuffix(len(missing), 3)+"), so whether their licences could be read is unknown", run.Stderr))
	}
	if len(misplaced) > 0 {
		out.Errors = append(out.Errors, prefix+"put "+strconv.Itoa(len(misplaced))+" module(s) where "+
			"cicd did not look ("+strings.Join(firstN(misplaced, 3), "; ")+moreSuffix(len(misplaced), 3)+
			"), so Trivy could not read their licences")
	}
	if len(uncopied) > 0 {
		out.Errors = append(out.Errors, prefix+"downloaded "+strconv.Itoa(len(uncopied))+" module(s) "+
			"whose files could not be copied for Trivy ("+strings.Join(firstN(uncopied, 3), ", ")+
			moreSuffix(len(uncopied), 3)+"), so their licences were not read")
	}
	return out
}

// goNotServed reports a download the Go module proxy itself refused: it does not
// have, or will not serve, that module version.
func goNotServed(msg string) bool {
	return strings.Contains(msg, "proxy.golang.org") &&
		(strings.Contains(msg, "404 Not Found") || strings.Contains(msg, "410 Gone"))
}

// goRefLabel names a module and the go.mod that asked for it.
func goRefLabel(ref goModRef, by []string) string {
	if len(by) == 0 {
		return ref.String()
	}
	return ref.String() + " (" + by[0] + moreSuffix(len(by), 1) + ")"
}

// boundedLine is s's first line, cut to n bytes.
func boundedLine(s string, n int) string {
	s = strings.TrimSpace(firstLine(strings.TrimSpace(s)))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func lineSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out[l] = true
		}
	}
	return out
}

// goLicenceDownloadWarning says the Go licences come from modules cicd
// downloaded, which ones it could not, and how many of the go.mod files Trivy
// then listed. "" when there was nothing to download and nothing left out.
//
// cov is nil when the scan did not complete; the warning then claims nothing
// about what was read.
func goLicenceDownloadWarning(out goDownloadOutcome, cov *licenceCoverage) string {
	p := out.Plan
	notDownloaded := len(out.NotServed) + len(out.Failed)
	if len(p.Refs) == 0 && len(p.Local) == 0 && len(p.Rejected) == 0 {
		return ""
	}
	msg := "security license scan: go — cicd downloaded " + strconv.Itoa(out.Downloaded) + " of " +
		strconv.Itoa(len(p.Refs)) + " module(s) required by " + strconv.Itoa(len(p.GoMods)) +
		" go.mod file(s) from " + goModuleProxy + " (the Go module proxy only, never a module's own " +
		"host) so Trivy could read each module's licence."
	var gaps []string
	if len(out.NotServed) > 0 {
		gaps = append(gaps, strconv.Itoa(len(out.NotServed))+" not served by the Go module proxy, which "+
			"is what a private module looks like ("+strings.Join(firstN(out.NotServed, 3), ", ")+
			moreSuffix(len(out.NotServed), 3)+")")
	}
	if len(out.Failed) > 0 {
		gaps = append(gaps, strconv.Itoa(len(out.Failed))+" failed to download ("+
			strings.Join(firstN(out.Failed, 3), "; ")+moreSuffix(len(out.Failed), 3)+")")
	}
	if len(p.Local) > 0 {
		gaps = append(gaps, strconv.Itoa(len(p.Local))+" replaced by a local directory ("+
			strings.Join(firstN(p.Local, 3), ", ")+moreSuffix(len(p.Local), 3)+")")
	}
	if len(p.Rejected) > 0 {
		gaps = append(gaps, strconv.Itoa(len(p.Rejected))+" not passed to the go command ("+
			strings.Join(firstN(p.Rejected, 3), ", ")+moreSuffix(len(p.Rejected), 3)+")")
	}
	if len(gaps) > 0 {
		msg += " Not downloaded: " + strings.Join(gaps, "; ") + "."
		if notDownloaded > 0 {
			msg += " cicd has no Go credential input, so a module the proxy does not serve cannot be " +
				"fetched here, and its licence was not judged."
		} else {
			msg += " Their licences were not judged."
		}
	}
	if cov == nil {
		return msg + " The scan did not complete, so how many of those go.mod files it read is unknown."
	}
	read, unlisted := goModReadSplit(p.GoMods, *cov)
	switch read {
	case 0:
		msg += " Trivy listed the modules of none of the go.mod files"
	case len(p.GoMods):
		msg += " Trivy listed the modules of every go.mod file"
	default:
		msg += " Trivy listed the modules of " + strconv.Itoa(read) + " of the go.mod files"
	}
	if len(unlisted) > 0 {
		msg += "; it listed none for " + strconv.Itoa(len(unlisted)) + " (" +
			strings.Join(firstN(unlisted, 3), ", ") + moreSuffix(len(unlisted), 3) + "), which a go.mod " +
			"with no requirement explains and a skip-dirs or skip-files in the tree's trivy.yaml also " +
			"produces — those modules' licences were not judged"
	}
	return msg + ". Whether a listed module carries a licence is the dependency coverage line's to say."
}

// goModReadSplit sorts the go.mod files into those Trivy listed modules for and
// the rest, matching Trivy's gomod target path.
func goModReadSplit(gomods []string, cov licenceCoverage) (read int, unlisted []string) {
	listed := map[string]bool{}
	for _, e := range cov.Ecosystems {
		if e.Type != "gomod" {
			continue
		}
		for _, t := range e.Targets {
			listed[cleanRelPath(t)] = true
		}
	}
	for _, gm := range gomods {
		if listed[cleanRelPath(gm)] {
			read++
		} else {
			unlisted = append(unlisted, gm)
		}
	}
	return read, unlisted
}
