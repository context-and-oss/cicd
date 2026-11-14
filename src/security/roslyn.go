// The .NET security analyzers (Microsoft.CodeAnalysis.NetAnalyzers, bundled
// with the SDK) as a second SAST leg beside Opengrep, for C# and Visual Basic.
//
// Deliberately untagged: project classification, script rendering, SARIF
// projection, the severity table and every sentence the leg writes live here,
// so roslyn_test.go reaches all of it without Dagger. roslynexec.go holds the
// container and nothing that decides anything.
//
// Why a second engine. Opengrep matches syntax, so it cannot see across a
// method call or follow a value from a request parameter to a SQL string the
// way a compiler-backed dataflow analysis can. The CA3001–CA3012 rules do that
// on the compiler's own semantic model, and the rest of the security category
// (weak crypto, insecure deserializers, disabled certificate validation) is
// precise in the same way because it resolves the symbol being called rather
// than the text that names it. The two legs overlap on purpose; the merged
// SARIF carries both runs under their own driver names.
//
// What it costs, and the shape of the doctrine around it:
//
//  1. **It builds the consumer's code.** Analyzers run inside the compiler, so
//     there is no analysis without a `dotnet build`, which evaluates the
//     consumer's MSBuild — the same trust the lockfile-free restore already
//     extends, and the same container posture: no host mount, the feed token as
//     a Dagger secret. A build that could not run is a non-run, never a pass.
//
//  2. **A project that produced no analyzer log was not analysed**, whatever
//     its build exit status says, and one whose compile had errors was analysed
//     over an incomplete program. Both are counted on the row (Examined) and
//     named in warnings, the same contract as a file Opengrep read in part.
//
//  3. **Projects cicd cannot build are named, never dropped.** A legacy
//     (non-SDK) project file needs MSBuild on Windows and a workload-only
//     project (MAUI, Android, iOS) needs a workload the pinned SDK does not
//     carry. They stay in Examined.Total so the row reads short, and a warning
//     says why. A tree of nothing else is a skipped row with that warning
//     rather than a permanent red the consumer cannot clear.
//
//  4. **cicd grades by its own table.** The consumer's .editorconfig can
//     downgrade a rule to a suggestion; the gate does not take the graded
//     party's word for how bad its own finding is (see roslynSeverity). A rule
//     the consumer switched off entirely did not run, and that is a narrowing,
//     disclosed by name.
package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// roslynToolName is the row name and the SARIF driver name, so a finding
	// joins to its row by the same string.
	roslynToolName = "roslyn-analyzers"

	// roslynMount is where the tree is copied for the build. The same mount as
	// the restore and Trivy, so a path in a message names the file a finding
	// elsewhere in the report names.
	roslynMount = dotnetRestoreMount

	// Fixed container paths. Nothing consumer-supplied reaches them.
	roslynDir          = "/cicd-roslyn"
	roslynOutDir       = roslynDir + "/out"
	roslynTargetsPath  = roslynDir + "/cicd.targets"
	roslynProjectsPath = "/tmp/roslyn.projects"
	roslynFailedPath   = "/tmp/roslyn.failed"
	roslynOutPath      = "/tmp/roslyn.out"
	roslynErrPath      = "/tmp/roslyn.err"

	// roslynSecurityCategory is the rule category the leg keeps. Every other
	// category (style, performance, reliability) belongs to quality, not to a
	// security gate.
	roslynSecurityCategory = "Security"

	// roslynExamplesShown bounds every list a warning names.
	roslynExamplesShown = 10
)

// roslynProjectGlobs are the project files the leg discovers. F# is
// discovered only so it can be named as uncovered: the analyzers' security
// rules are written for C# and Visual Basic.
var roslynProjectGlobs = []string{"**/*.csproj", "**/*.vbproj", "**/*.fsproj"}

// roslynBuildArgs are the arguments every per-project build gets after the
// project path. Global properties, so they win over anything the project
// file sets and flow into every project it references:
//
//   - AnalysisModeSecurity=All turns on every rule in the security category,
//     including the ones the SDK ships disabled; RunAnalyzers,
//     RunAnalyzersDuringBuild and EnableNETAnalyzers undo a project that
//     switched analysis off. A rule still off after this was switched off by
//     the repository's own rule configuration, which is the narrowing the
//     leg discloses.
//   - TreatWarningsAsErrors=false keeps a findings-as-errors project from
//     failing its compile on the findings cicd is here to collect.
//   - EnableWindowsTargeting lets a WinForms or WPF project build on Linux.
//   - CustomAfterMicrosoftCommonTargets imports the one file that sets where
//     the compiler writes its SARIF (roslynTargets).
//   - No node reuse and no shared compilation: nothing outlives the exec.
//
// Not --no-incremental: a referenced project built during an earlier
// project's build has already left its log, and rebuilding it would only
// repeat the work.
var roslynBuildArgs = []string{
	"-nologo",
	"-v:q",
	"-clp:ErrorsOnly",
	"-nodeReuse:false",
	"-p:UseSharedCompilation=false",
	"-p:AnalysisModeSecurity=All",
	"-p:RunAnalyzers=true",
	"-p:RunAnalyzersDuringBuild=true",
	"-p:EnableNETAnalyzers=true",
	"-p:TreatWarningsAsErrors=false",
	"-p:EnableWindowsTargeting=true",
	"-p:CustomAfterMicrosoftCommonTargets=" + roslynTargetsPath,
}

// roslynTargets is imported into every project build. It points the
// compiler's ErrorLog at a fresh file per compile and writes the project's
// full path beside it, so each log can be attributed to the project that
// produced it.
//
// It sets ErrorLog inside a target that runs just before CoreCompile rather
// than as a static property, because a static property can be overwritten by
// anything the repository imports later (Directory.Build.targets among them).
// A repository can still replace it from a target of its own; the log it
// would then point at is not the one cicd reads, so the project reads as not
// analysed, which is loud, not clean.
//
// A GUID rather than a name derived from the path: a flattened path can
// exceed a filename's length, and two target frameworks of one project need
// two files.
const roslynTargets = `<Project>
  <Target Name="CicdRoslynErrorLog" BeforeTargets="CoreCompile">
    <PropertyGroup>
      <CicdRoslynLogId>$([System.Guid]::NewGuid().ToString('N'))</CicdRoslynLogId>
      <ErrorLog>` + roslynOutDir + `/$(CicdRoslynLogId).sarif,version=2.1</ErrorLog>
    </PropertyGroup>
    <MakeDir Directories="` + roslynOutDir + `" />
    <WriteLinesToFile File="` + roslynOutDir + `/$(CicdRoslynLogId).project" Lines="$([MSBuild]::Escape($(MSBuildProjectFullPath)))" Overwrite="true" />
  </Target>
</Project>
`

// roslynBuildScript renders the shell body of the build.
//
// The project list is written by Go to roslynProjectsPath and read line by
// line into a quoted "$p": a project path is consumer-controlled and is an
// argument here, never shell source. The fixed arguments are cicd constants
// (TestRoslynScriptIsShellSafe). Each project is built on its own so each has
// its own exit status, and every failure is written down by name; the script
// always exits 0 and Go classifies.
func roslynBuildScript() string {
	return "mkdir -p " + roslynOutDir + "\n" +
		": > " + roslynFailedPath + "\n" +
		": > " + roslynOutPath + "\n" +
		": > " + roslynErrPath + "\n" +
		"while IFS= read -r p; do\n" +
		"  [ -n \"$p\" ] || continue\n" +
		"  if ! dotnet build \"$p\" " + strings.Join(roslynBuildArgs, " ") +
		" >>" + roslynOutPath + " 2>>" + roslynErrPath + "; then\n" +
		"    printf '%s\\n' \"$p\" >> " + roslynFailedPath + "\n" +
		"  fi\n" +
		"done < " + roslynProjectsPath + "\n" +
		"exit 0"
}

// roslynProjectsFile renders the project list the script reads, one absolute
// container path per line.
func roslynProjectsFile(projects []string) string {
	var b strings.Builder
	for _, p := range projects {
		b.WriteString(roslynMount + "/" + p + "\n")
	}
	return b.String()
}

// --- scope ------------------------------------------------------------------

// roslynScope is what discovery found, before anything is built.
type roslynScope struct {
	// Build is every C#/VB project cicd will build, mount-relative.
	Build []string
	// Uncovered is every C#/VB project cicd cannot build, with the reason.
	Uncovered []roslynUncovered
	// FSharp is every F# project, which the analyzers do not cover.
	FSharp []string
}

type roslynUncovered struct {
	Path, Reason string
}

// total is the row's denominator: every C#/VB project, buildable or not. F#
// is not in it, because the unit is "C#/VB projects".
func (s roslynScope) total() int { return len(s.Build) + len(s.Uncovered) }

// empty says the tree has no .NET project of any kind, so the leg has no row.
func (s roslynScope) empty() bool { return s.total() == 0 && len(s.FSharp) == 0 }

var (
	// An SDK-style project names its SDK on <Project Sdk=…>, on an
	// <Import Sdk=…> or in an <Sdk Name=…/> element. A project with none of
	// the three is the legacy format, which needs the .NET Framework MSBuild.
	roslynSDKMarker = regexp.MustCompile(`(?i)<Project[^>]*\sSdk\s*=|<Import[^>]*\sSdk\s*=|<Sdk\s+Name\s*=`)
	roslynUseMaui   = regexp.MustCompile(`(?i)<UseMaui>\s*true\s*</UseMaui>`)
	roslynTFMs      = regexp.MustCompile(`(?is)<TargetFrameworks?>(.*?)</TargetFrameworks?>`)
	// A platform suffix that needs a workload the pinned SDK image does not
	// install. "-windows" is not here: EnableWindowsTargeting builds it.
	roslynWorkloadTFM = regexp.MustCompile(`(?i)-(android|ios|maccatalyst|macos|tvos|tizen|browser)`)
)

// classifyRoslynProjects sorts discovered project files by what the leg can do
// with them. contents maps a mount-relative path to the project file's text.
func classifyRoslynProjects(contents map[string]string) roslynScope {
	paths := make([]string, 0, len(contents))
	for p := range contents {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var s roslynScope
	for _, p := range paths {
		lower := strings.ToLower(p)
		if strings.HasSuffix(lower, ".fsproj") {
			s.FSharp = append(s.FSharp, p)
			continue
		}
		if reason := roslynUnbuildable(p, contents[p]); reason != "" {
			s.Uncovered = append(s.Uncovered, roslynUncovered{Path: p, Reason: reason})
			continue
		}
		s.Build = append(s.Build, p)
	}
	return s
}

// roslynUnbuildable says why cicd cannot build a project, or "" when it can.
func roslynUnbuildable(path, body string) string {
	if strings.ContainsAny(path, "\n\r") {
		// The script reads one path per line; this one would be read as two.
		return "its path holds a line break"
	}
	if !roslynSDKMarker.MatchString(body) {
		return "legacy (non-SDK) project format, which needs the .NET Framework MSBuild"
	}
	if roslynUseMaui.MatchString(body) {
		return "a .NET MAUI project, which needs a workload the pinned SDK does not install"
	}
	var tfms []string
	for _, m := range roslynTFMs.FindAllStringSubmatch(body, -1) {
		for _, t := range strings.Split(m[1], ";") {
			if t = strings.TrimSpace(t); t != "" {
				tfms = append(tfms, t)
			}
		}
	}
	if len(tfms) == 0 {
		return ""
	}
	for _, t := range tfms {
		// A property reference is a value cicd cannot evaluate here; building
		// it is the only way to find out.
		if strings.Contains(t, "$(") || !roslynWorkloadTFM.MatchString(t) {
			return ""
		}
	}
	return "every target framework (" + strings.Join(tfms, ";") + ") needs a workload the pinned SDK does not install"
}

// --- the compiler's SARIF ---------------------------------------------------

type roslynLog struct {
	// Project is the mount-relative project path from the sidecar, "" when
	// the sidecar was missing or named a file outside the mount.
	Project string
	SARIF   []byte
}

type roslynDoc struct {
	Runs []roslynDocRun `json:"runs"`
}

type roslynDocRun struct {
	Tool struct {
		Driver struct {
			Name            string          `json:"name"`
			SemanticVersion string          `json:"semanticVersion"`
			Rules           []roslynDocRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Invocations []struct {
		RuleConfigurationOverrides []struct {
			Descriptor struct {
				ID    string `json:"id"`
				Index *int   `json:"index"`
			} `json:"descriptor"`
			Configuration roslynRuleConfig `json:"configuration"`
		} `json:"ruleConfigurationOverrides"`
	} `json:"invocations"`
	Results []roslynDocResult `json:"results"`
}

type roslynRuleConfig struct {
	Enabled *bool  `json:"enabled"`
	Level   string `json:"level"`
}

func (c roslynRuleConfig) on() bool {
	return (c.Enabled == nil || *c.Enabled) && c.Level != "none"
}

type roslynDocRule struct {
	ID               string            `json:"id"`
	ShortDescription *roslynText       `json:"shortDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	DefaultConfig    *roslynRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties       struct {
		Category string `json:"category"`
	} `json:"properties"`
}

type roslynText struct {
	Text string `json:"text"`
}

type roslynDocResult struct {
	RuleID       string           `json:"ruleId"`
	RuleIndex    *int             `json:"ruleIndex"`
	Level        string           `json:"level"`
	Message      roslynText       `json:"message"`
	Locations    []roslynLocation `json:"locations"`
	Suppressions []struct {
		Kind   string `json:"kind"`
		Status string `json:"status"`
	} `json:"suppressions"`
}

type roslynLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *roslynRegion `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

type roslynRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// roslynCompilerError matches a compiler diagnostic: C# CSnnnn, VB BCnnnnn.
// An analyzer rule (CA, ASP, …) at level error is a finding, not a failed
// compile.
var roslynCompilerError = regexp.MustCompile(`^(CS|BC)[0-9]+$`)

// securityRules returns the security rules a run had switched on, by id, with
// their descriptors, and the ones it had switched off. Precedence follows the
// compiler's own: an invocation override, then the rule's default.
func (run roslynDocRun) securityRules() (on map[string]roslynDocRule, off []string) {
	overrides := map[string]roslynRuleConfig{}
	for _, inv := range run.Invocations {
		for _, o := range inv.RuleConfigurationOverrides {
			id := o.Descriptor.ID
			if id == "" && o.Descriptor.Index != nil && *o.Descriptor.Index >= 0 && *o.Descriptor.Index < len(run.Tool.Driver.Rules) {
				id = run.Tool.Driver.Rules[*o.Descriptor.Index].ID
			}
			if id != "" {
				overrides[id] = o.Configuration
			}
		}
	}
	on = map[string]roslynDocRule{}
	for _, r := range run.Tool.Driver.Rules {
		if r.Properties.Category != roslynSecurityCategory {
			continue
		}
		enabled := r.DefaultConfig == nil || r.DefaultConfig.on()
		if o, ok := overrides[r.ID]; ok {
			enabled = o.on()
		}
		if enabled {
			on[r.ID] = r
		} else {
			off = append(off, r.ID)
		}
	}
	return on, off
}

// --- severity ---------------------------------------------------------------

// roslynSeverity is cicd's grade for a security rule, independent of whatever
// level the repository configured.
//
// HIGH is reserved for rules whose finding is, on its own, an exploitable
// shape rather than a weakness to review:
//
//   - CA3001–CA3012: the compiler's dataflow traced untrusted input to an
//     injection sink (SQL, command, path, XSS, LDAP, XPath, XML, regex,
//     open redirect, code). The precise class of finding Opengrep cannot make.
//   - CA2300–CA2330, CA2350–CA2362: deserializers that execute types named by
//     the payload (BinaryFormatter, NetDataContractSerializer, LosFormatter,
//     JSON.NET with type names, DataSet from untrusted XML).
//   - CA5360: calling dangerous methods during deserialization.
//   - CA5359: certificate validation switched off.
//
// Everything else — weak hashes and ciphers, ECB, insecure RNG, missing
// HSTS, TLS version pins, rules cicd has not seen — is MEDIUM: real, worth a
// report, and not a reason to stop a release at the default threshold.
func roslynSeverity(ruleID string) Severity {
	in := func(lo, hi string) bool {
		return len(ruleID) == len(lo) && ruleID >= lo && ruleID <= hi
	}
	switch {
	case in("CA3001", "CA3012"),
		in("CA2300", "CA2330"),
		in("CA2350", "CA2362"),
		ruleID == "CA5360",
		ruleID == "CA5359":
		return SeverityHigh
	}
	return SeverityMedium
}

func roslynLevel(s Severity) string {
	if s == SeverityHigh {
		return "error"
	}
	return "warning"
}

// --- projection and classification -----------------------------------------

// roslynOutcome is what the build container reported back.
type roslynOutcome struct {
	Band, BandNote string
	// Failed is every project whose build exited non-zero, mount-relative.
	Failed []string
	// Output is the build's console (errors only) and Stderr its stderr.
	Output, Stderr string
	Logs           []roslynLog
}

// roslynResult is the leg's contribution to the envelope.
type roslynResult struct {
	// Present is false when the tree has no .NET project: the leg has no row.
	Present    bool
	SARIF      json.RawMessage
	BySeverity map[Severity]int
	Examined   *Examined
	Rules      *RuleSet
	Warnings   []string
	Skipped    bool
	Err        error
}

// roslynExamined is the unit the row counts in.
const roslynExamined = "C#/VB projects"

// roslynScopeOnly is the result when nothing was built: no C#/VB project
// cicd can build. Skipped, with the reason named, never a clean zero.
func roslynScopeOnly(s roslynScope) roslynResult {
	if s.empty() {
		return roslynResult{}
	}
	r := roslynResult{
		Present:  true,
		Skipped:  true,
		Examined: &Examined{Unit: roslynExamined, Count: 0, Total: s.total()},
		Warnings: roslynScopeWarnings(s),
	}
	r.Warnings = append(r.Warnings, roslynToolName+": SKIPPED — no C# or Visual Basic project in this tree "+
		"is one cicd can build, so no security analyzer ran. Opengrep's C# rules still ran; the compiler-backed "+
		"dataflow rules (CA3001–CA3012) did not.")
	return r
}

func roslynScopeWarnings(s roslynScope) []string {
	var w []string
	if len(s.Uncovered) > 0 {
		names := make([]string, 0, len(s.Uncovered))
		for _, u := range s.Uncovered {
			names = append(names, u.Path+" ("+u.Reason+")")
		}
		w = append(w, fmt.Sprintf("%s: %d C#/VB %s not analysed because cicd cannot build %s: %s",
			roslynToolName, len(s.Uncovered), pick(len(s.Uncovered), "project was", "projects were"),
			pick(len(s.Uncovered), "it", "them"), strings.Join(firstN(names, roslynExamplesShown), "; ")))
	}
	if len(s.FSharp) > 0 {
		w = append(w, fmt.Sprintf("%s: %d F# %s not covered — the .NET security analyzers analyse C# and "+
			"Visual Basic only: %s", roslynToolName, len(s.FSharp), pick(len(s.FSharp), "project is", "projects are"),
			strings.Join(firstN(s.FSharp, roslynExamplesShown), ", ")))
	}
	return w
}

// analyseRoslyn turns the build's logs into the leg's result.
func analyseRoslyn(s roslynScope, out roslynOutcome) roslynResult {
	res := roslynResult{Present: true, Warnings: roslynScopeWarnings(s)}
	if out.BandNote != "" {
		res.Warnings = append(res.Warnings, roslynToolName+": "+out.BandNote)
	}

	failed := map[string]bool{}
	for _, p := range out.Failed {
		failed[p] = true
	}
	inBuild := map[string]bool{}
	for _, p := range s.Build {
		inBuild[p] = true
	}

	type kept struct {
		result roslynDocResult
		key    string
	}
	var (
		results    []kept
		seen       = map[string]bool{}
		rulesOn    = map[string]roslynDocRule{}
		offIn      = map[string]map[string]bool{} // rule → projects that switched it off
		analysed   = map[string]bool{}
		partial    = map[string]bool{}
		unreadable int
		outside    = map[string]bool{}
		version    string
	)

	for _, log := range out.Logs {
		var doc roslynDoc
		if err := json.Unmarshal(log.SARIF, &doc); err != nil {
			unreadable++
			continue
		}
		for _, run := range doc.Runs {
			if version == "" {
				version = run.Tool.Driver.SemanticVersion
			}
			on, off := run.securityRules()
			if len(on) == 0 {
				// Analyzers did not run on this compile at all; it analysed
				// nothing, whatever results it carries.
				continue
			}
			if inBuild[log.Project] {
				analysed[log.Project] = true
			}
			for id, r := range on {
				rulesOn[id] = r
			}
			for _, id := range off {
				if offIn[id] == nil {
					offIn[id] = map[string]bool{}
				}
				offIn[id][log.Project] = true
			}
			for _, r := range run.Results {
				if roslynCompilerError.MatchString(r.RuleID) && r.Level == "error" {
					if inBuild[log.Project] {
						partial[log.Project] = true
					}
					continue
				}
				desc, ok := on[r.RuleID]
				if !ok || desc.Properties.Category != roslynSecurityCategory {
					continue
				}
				proj, ok := roslynProjectResult(r)
				if !ok {
					// Counted once per finding, not once per compile that saw it.
					outside[roslynResultKey(r)] = true
					continue
				}
				key := roslynResultKey(proj)
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, kept{proj, key})
			}
		}
	}
	for p := range analysed {
		if failed[p] {
			partial[p] = true
		}
	}

	var notAnalysed []string
	for _, p := range s.Build {
		if !analysed[p] {
			notAnalysed = append(notAnalysed, p)
		}
	}

	res.Examined = &Examined{Unit: roslynExamined, Count: len(analysed), Total: s.total(), Partial: len(partial)}

	if len(analysed) == 0 {
		res.Err = fmt.Errorf("%s: SAST did not run — none of the %d C#/VB %s cicd built produced an analyzer log%s",
			roslynToolName, len(s.Build), pick(len(s.Build), "project", "projects"), roslynBuildDiagnosis(out))
		return res
	}

	if unreadable > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d analyzer %s could not be parsed as SARIF and "+
			"were not read", roslynToolName, unreadable, pick(unreadable, "log", "logs")))
	}
	if len(notAnalysed) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d of %d C#/VB projects %s not analysed — the build produced "+
			"no analyzer log for %s, so no security rule ran on %s code: %s%s",
			roslynToolName, len(notAnalysed), s.total(), pick(len(notAnalysed), "was", "were"),
			pick(len(notAnalysed), "it", "them"), pick(len(notAnalysed), "its", "their"),
			strings.Join(firstN(notAnalysed, roslynExamplesShown), ", "), roslynBuildDiagnosis(out)))
	}
	if len(partial) > 0 {
		names := sortedKeys(partial)
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: PARTIAL SCAN — %d analysed %s did not build cleanly "+
			"(a compiler error, or a build step that failed), so the analyzers may have seen an incomplete "+
			"program and findings there are a floor: %s", roslynToolName, len(partial),
			pick(len(partial), "project", "projects"), strings.Join(firstN(names, roslynExamplesShown), ", ")))
	}
	if len(offIn) > 0 {
		ids := make([]string, 0, len(offIn))
		for id, projects := range offIn {
			ids = append(ids, id+" ("+strconv.Itoa(len(projects))+")")
		}
		sort.Strings(ids)
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: NARROWED RULES — %d security %s switched off by the "+
			"repository's own configuration (NoWarn, .editorconfig, a global config or a ruleset) and did not "+
			"run; projects that switched each off in brackets: %s", roslynToolName, len(offIn),
			pick(len(offIn), "rule was", "rules were"), strings.Join(firstN(ids, roslynExamplesShown*2), ", ")))
	}
	if outsideRoot := len(outside); outsideRoot > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d %s outside the scanned tree or in build "+
			"output (generated or package code) %s not reported", roslynToolName, outsideRoot, pick(outsideRoot, "finding", "findings"),
			pick(outsideRoot, "was", "were")))
	}

	// The projected run. Rules are every security rule that ran anywhere,
	// graded by cicd's table; results carry the level that grade implies.
	ids := make([]string, 0, len(rulesOn))
	for id := range rulesOn {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		r := rulesOn[id]
		rule := map[string]any{
			"id":                   id,
			"defaultConfiguration": map[string]any{"level": roslynLevel(roslynSeverity(id))},
			"properties":           map[string]any{"category": roslynSecurityCategory},
		}
		if r.ShortDescription != nil && r.ShortDescription.Text != "" {
			rule["shortDescription"] = r.ShortDescription
		}
		if r.HelpURI != "" {
			rule["helpUri"] = r.HelpURI
		}
		rules = append(rules, rule)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].key < results[j].key })
	outResults := make([]map[string]any, 0, len(results))
	res.BySeverity = map[Severity]int{}
	for _, k := range results {
		r := k.result
		sev := roslynSeverity(r.RuleID)
		entry := map[string]any{
			"ruleId":  r.RuleID,
			"level":   roslynLevel(sev),
			"message": r.Message,
		}
		if len(r.Locations) > 0 {
			entry["locations"] = r.Locations
		}
		if len(r.Suppressions) > 0 {
			sup := make([]map[string]string, 0, len(r.Suppressions))
			accepted := false
			for _, s := range r.Suppressions {
				m := map[string]string{"kind": s.Kind}
				if s.Status != "" {
					m["status"] = s.Status
				}
				if s.Status == "" || s.Status == "accepted" {
					accepted = true
				}
				sup = append(sup, m)
			}
			entry["suppressions"] = sup
			if accepted {
				outResults = append(outResults, entry)
				continue
			}
		}
		res.BySeverity[sev]++
		outResults = append(outResults, entry)
	}

	driver := map[string]any{"name": roslynToolName, "rules": rules}
	if version != "" {
		driver["semanticVersion"] = version
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":              map[string]any{"driver": driver},
			"automationDetails": map[string]any{"id": roslynToolName},
			"columnKind":        "utf16CodeUnits",
			"results":           outResults,
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		res.Err = fmt.Errorf("%s: could not encode the projected SARIF: %w", roslynToolName, err)
		return res
	}
	res.SARIF = raw
	if w := sarifSuppressionWarning(roslynToolName, raw); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	res.Rules = &RuleSet{Count: len(rulesOn), Pinned: dotnetRestoreImageLabel(out.Band) + " (bundled analyzers)"}
	return res
}

// roslynProjectResult keeps a result's allowlisted fields with its locations
// made relative to the scanned tree. False when its primary location is
// outside the tree: generated or package code is not the consumer's source,
// and an absolute container path in the evidence names nothing they have.
func roslynProjectResult(r roslynDocResult) (roslynDocResult, bool) {
	out := roslynDocResult{RuleID: r.RuleID, Message: r.Message, Suppressions: r.Suppressions}
	for i, loc := range r.Locations {
		rel, ok := roslynRelativeURI(loc.PhysicalLocation.ArtifactLocation.URI)
		if !ok {
			if i == 0 {
				return roslynDocResult{}, false
			}
			continue
		}
		var l roslynLocation
		l.PhysicalLocation.ArtifactLocation.URI = rel
		l.PhysicalLocation.Region = loc.PhysicalLocation.Region
		out.Locations = append(out.Locations, l)
	}
	return out, true
}

// roslynRelativeURI maps the compiler's absolute file URI to a path relative
// to the scanned tree, as Opengrep's results are.
func roslynRelativeURI(uri string) (string, bool) {
	prefix := "file://" + roslynMount + "/"
	if !strings.HasPrefix(uri, prefix) {
		return "", false
	}
	rel := strings.TrimPrefix(uri, prefix)
	if rel == "" {
		return "", false
	}
	// Traversal is outside the tree; bin/ and obj/ are build output — source
	// generators and SDK-generated files the consumer never wrote and cannot
	// open in their checkout.
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." || seg == "bin" || seg == "obj" {
			return "", false
		}
	}
	return rel, true
}

// roslynResultKey identifies one finding across the logs of a multi-targeted
// project and across projects that compile the same file: rule, place and
// message. The message stays in the key because two findings of one rule on
// one span can name different sinks.
func roslynResultKey(r roslynDocResult) string {
	var b strings.Builder
	b.WriteString(r.RuleID)
	for _, l := range r.Locations {
		b.WriteString("|" + l.PhysicalLocation.ArtifactLocation.URI)
		if g := l.PhysicalLocation.Region; g != nil {
			fmt.Fprintf(&b, ":%d:%d:%d:%d", g.StartLine, g.StartColumn, g.EndLine, g.EndColumn)
		}
	}
	b.WriteString("|" + r.Message.Text)
	return b.String()
}

// roslynBuildDiagnosis names the first build error, for a message that has to
// say why a project produced no log. MSBuild writes errors to the console,
// not stderr, so the console is read first.
func roslynBuildDiagnosis(out roslynOutcome) string {
	for _, src := range []string{out.Output, out.Stderr} {
		for _, line := range strings.Split(src, "\n") {
			if line = strings.TrimSpace(line); strings.Contains(line, ": error ") {
				return " (first build error: " + roslynTrimMount(line) + ")"
			}
		}
	}
	if s := strings.TrimSpace(out.Stderr); s != "" {
		return " (stderr: " + roslynTrimMount(firstLine(s)) + ")"
	}
	return ""
}

// roslynTrimMount makes container paths in a build message read as the
// consumer's own.
func roslynTrimMount(s string) string {
	return strings.ReplaceAll(s, roslynMount+"/", "")
}

// roslynSidecarProject maps a sidecar's content (the project's full container
// path) to the mount-relative path the scope uses.
func roslynSidecarProject(raw string) string {
	p := strings.TrimSpace(raw)
	if !strings.HasPrefix(p, roslynMount+"/") {
		return ""
	}
	return relativeToMount(roslynMount, p)
}

// roslynInBuildOutput says a discovered project file sits in a bin/ or obj/
// directory — a copy the build made, not a project the consumer wrote.
func roslynInBuildOutput(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "bin" || seg == "obj" {
			return true
		}
	}
	return false
}

// pick chooses a word by count, without the count (apireach's plural writes
// the count too, and these sentences place it elsewhere).
func pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
