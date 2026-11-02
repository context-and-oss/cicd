// SDK band selection: which pinned .NET SDK band a repository asks for, and
// which band cicd runs it in.
//
// Deliberately untagged (no //go:build !unit_test): this is string parsing and
// comparison, so each module's unit suite drives it under `-tags unit_test`.
//
// The same file exists in src/quality and src/security, because Dagger modules
// share no Go; keep them byte-identical (scripts/repo-inventory.json
// synced_files refuses a drift). quality selects a band to lint and test in,
// security one to restore the dependency graph in, and the two must agree on
// the rule: a module that resolved the same repository to a different band
// would attribute its verdict to an SDK the other never used. What differs
// between them — the NETSDK1045 relay and the target sweep in quality, the
// restore classification in security — lives in each module's own files. The
// two band constants live in each module's images.go.
package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// dotnetSDKBands are the SDK bands cicd pins an image for, ascending. It is the
// authority on what cicd can serve: every message that offers a band, and every
// resolution below, reads it rather than restating a list.
var dotnetSDKBands = []string{dotnetSDK80Band, dotnetSDK100Band}

// dotnetBandRequest is what the repository asks of the SDK, and where that came
// from. Band is "" when nothing readable said anything, which is a real answer
// and not an error: a TargetFramework can live behind an MSBuild condition, and
// most repositories have no global.json at all.
type dotnetBandRequest struct {
	Band   string
	Source string // one of the dotnetBandSource* constants, or "" for no request
}

// dotnetBandSource* name where a band request came from. Spelled once because
// the value is both prose inside dotnetResolveBand's note and a value callers
// switch on to report provenance; a literal in two places is how the
// accepted-language set drifted from its shell case statement.
const (
	dotnetBandSourceGlobalJSON = "global.json"
	dotnetBandSourceTFM        = "TargetFramework"
)

// dotnetResolveBand picks the pinned band to use and the note that records why.
//
// The rule is: the lowest pinned band that is at least the requested one, since
// a newer SDK builds and restores an older target but never the reverse.
// Nothing requested resolves to the lowest pinned band.
//
// A band above everything pinned resolves to the highest pinned band, not to a
// refusal, and this is the load-bearing choice in the function. The request is
// read from files cicd cannot fully evaluate, so a `net11.0` inside a
// conditioned TargetFrameworks element may never be built at all, and refusing
// would turn a working repository red on a string. Using the newest band keeps
// the verdict with the SDK: if the tree really needs the newer band, the build
// or restore fails, each module classifies that as a non-run, and gatedPassed
// fails it at every threshold including NONE. A band cicd cannot serve
// therefore still fails loud — on evidence rather than on a guess.
func dotnetResolveBand(req dotnetBandRequest) (string, string) {
	lowest, highest := dotnetSDKBands[0], dotnetSDKBands[len(dotnetSDKBands)-1]

	if _, _, ok := dotnetBand(req.Band); !ok {
		// Includes the ordinary Band == "" case. A request that is not a band is
		// no request: nothing here may invent one.
		return lowest, "SDK band " + lowest + " (no global.json sdk.version and no " +
			"literal TargetFramework to read, so cicd's oldest pinned band is used)"
	}

	from := " (requested by " + req.Source + ")"
	for _, pinned := range dotnetSDKBands {
		cmp, ok := dotnetBandCompare(pinned, req.Band)
		if !ok {
			continue
		}
		if cmp == 0 {
			return pinned, "SDK band " + pinned + from
		}
		if cmp > 0 {
			return pinned, "SDK band " + pinned + ": " + req.Source + " asks for " +
				req.Band + ", which cicd pins no image for; using the nearest " +
				"pinned band above it, which can build it"
		}
	}

	return highest, "SDK band " + highest + ": " + req.Source + " asks for " +
		req.Band + ", which is above every band cicd pins (" + dotnetBandsLabel() +
		"). Using the newest pinned band — if the tree genuinely needs " +
		req.Band + " it fails as a non-run, which no --fail-on threshold " +
		"forgives, and never as a clean pass"
}

// dotnetBandsLabel lists the SDK bands cicd pins, for a message that has to
// tell a consumer what is on offer.
func dotnetBandsLabel() string {
	return strings.Join(dotnetSDKBands, ", ")
}

// dotnetBandCompare orders two "<major>.<minor>" bands numerically. ok is false
// when either side is not a band, and a caller must not read that as equality.
func dotnetBandCompare(a, b string) (int, bool) {
	aMajor, aMinor, aOK := dotnetBand(a)
	bMajor, bMinor, bOK := dotnetBand(b)
	if !aOK || !bOK {
		return 0, false
	}
	switch {
	case aMajor != bMajor:
		return aMajor - bMajor, true
	case aMinor != bMinor:
		return aMinor - bMinor, true
	default:
		return 0, true
	}
}

// dotnetBand splits a "<major>.<minor>" band into numbers.
func dotnetBand(s string) (int, int, bool) {
	major, minor, found := strings.Cut(strings.TrimSpace(s), ".")
	if !found {
		return 0, 0, false
	}
	ma, err := strconv.Atoi(major)
	if err != nil {
		return 0, 0, false
	}
	mi, err := strconv.Atoi(minor)
	if err != nil {
		return 0, 0, false
	}
	return ma, mi, true
}

// dotnetProbe* delimit the two sections of the band probe: global.json, then the
// concatenated project files. Two sections in one container execution, and kept
// off any stream that also carries file paths on purpose: project-file contents
// are read here, and such a stream could report a target framework from a
// project that was never on disk.
const (
	dotnetProbeGlobalJSON = "===CICD-GLOBALJSON==="
	dotnetProbeTFM        = "===CICD-TFM==="
)

// parseDotnetBandRequest reads the band probe. global.json wins over the project
// files because it is the consumer's explicit statement about which SDK to use,
// and because honouring it is what keeps exit 145 and NETSDK1045 off the table:
// selecting some other band while a global.json names this one is precisely how
// the pinned SDK and the requested SDK used to disagree.
func parseDotnetBandRequest(raw string) dotnetBandRequest {
	_, rest, ok := strings.Cut(raw, dotnetProbeGlobalJSON)
	if !ok {
		return dotnetBandRequest{}
	}
	globalJSON, projects, ok := strings.Cut(rest, dotnetProbeTFM)
	if !ok {
		globalJSON, projects = rest, ""
	}
	if band, ok := dotnetBandFromGlobalJSON(globalJSON); ok {
		return dotnetBandRequest{Band: band, Source: dotnetBandSourceGlobalJSON}
	}
	if band := dotnetHighestTFM(projects); band != "" {
		return dotnetBandRequest{Band: band, Source: dotnetBandSourceTFM}
	}
	return dotnetBandRequest{}
}

// dotnetBandFromGlobalJSON reads the major.minor of a global.json's sdk.version.
//
// It selects among cicd's pinned bands, so it takes the file contents and is
// not quality's ADR-004 resolver in toolchain.go, which answers a different
// question: which unpinned tag to run a consumer's own command in.
//
// Unreadable, absent or malformed is ok=false, never an error: the project files
// are the next answer, and the lowest pinned band after that.
func dotnetBandFromGlobalJSON(raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	var doc struct {
		Sdk struct {
			Version string `json:"version"`
		} `json:"sdk"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &doc); err != nil {
		return "", false
	}
	parts := strings.Split(strings.TrimSpace(doc.Sdk.Version), ".")
	if len(parts) < 2 {
		return "", false
	}
	band := parts[0] + "." + parts[1]
	if _, _, ok := dotnetBand(band); !ok {
		return "", false
	}
	return band, true
}

// dotnetTargetFrameworkElement isolates the TargetFramework(s) elements, so a
// version mentioned anywhere else in the project file — a PackageReference, an
// analyser path — cannot be read as the target.
var dotnetTargetFrameworkElement = regexp.MustCompile(
	`(?is)<TargetFrameworks?>(.*?)</TargetFrameworks?>`)

// dotnetProjectTFMPattern matches literal target frameworks inside such an
// element: `net10.0`, and each entry of a `net8.0;net10.0` list. Only
// `net<major>.<minor>` is matched — `net48`, `netstandard2.0` and anything
// MSBuild has to evaluate (`$(DefaultTargetFramework)`) are older or unknowable,
// and neither can be above the pin in a way worth guessing about.
var dotnetProjectTFMPattern = regexp.MustCompile(`(?i)net(\d+)\.(\d+)`)

// dotnetHighestTFM reports the highest literal `net<major>.<minor>` target
// framework declared inside a `<TargetFramework(s)>` element anywhere in the
// given text, or "" when there is none to read. It never compares against a
// band: one caller uses it to choose the SDK before anything runs, and quality
// also uses it to explain a failure that already happened. Neither may invent a
// framework the text did not state.
func dotnetHighestTFM(text string) string {
	best := ""
	bestMajor, bestMinor := -1, -1
	for _, el := range dotnetTargetFrameworkElement.FindAllStringSubmatch(text, -1) {
		for _, m := range dotnetProjectTFMPattern.FindAllStringSubmatch(el[1], -1) {
			major, minor, ok := dotnetBand(m[1] + "." + m[2])
			if !ok {
				continue
			}
			if major > bestMajor || (major == bestMajor && minor > bestMinor) {
				best, bestMajor, bestMinor = m[1]+"."+m[2], major, minor
			}
		}
	}
	return best
}
