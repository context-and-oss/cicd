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
	"crypto/sha256"
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
	roslynSolutionPath = roslynDir + "/cicd-roslyn.sln"
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

// roslynBuildArgs are the arguments every build gets after the solution or
// project path: the combined build (which adds -m) and each per-project
// fallback build. Global properties, so they win over anything the project
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
//     The combined build's worker nodes end with that one call.
//
// Not --no-incremental: a project the combined build already compiled, or
// that an earlier fallback build compiled as a reference, has already left
// its log, and rebuilding it would only repeat the work.
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
//
// The other two targets stand in for the exit status a per-project build used
// to give: every project is built by one MSBuild call, which has one exit
// status for all of them. Each build instance writes a .started marker naming
// its project before BeforeBuild and a .built marker after Build. The start
// hooks BeforeBuild, the first target of Build's DependsOnTargets chain, not
// Build itself: MSBuild runs a target's DependsOnTargets before its
// BeforeTargets hooks, so a hook on Build would run only once the compile had
// already succeeded (measured). MSBuild runs an AfterTargets target only when
// the target it follows succeeded, so a .started with no matching .built is a
// build that failed (roslynMarkerFailures). A multi-targeted project's outer
// build does not import this file; its inner builds, one per framework, each
// mark their own.
const roslynTargets = `<Project>
  <Target Name="CicdRoslynErrorLog" BeforeTargets="CoreCompile">
    <PropertyGroup>
      <CicdRoslynLogId>$([System.Guid]::NewGuid().ToString('N'))</CicdRoslynLogId>
      <ErrorLog>` + roslynOutDir + `/$(CicdRoslynLogId).sarif,version=2.1</ErrorLog>
    </PropertyGroup>
    <MakeDir Directories="` + roslynOutDir + `" />
    <WriteLinesToFile File="` + roslynOutDir + `/$(CicdRoslynLogId).project" Lines="$([MSBuild]::Escape($(MSBuildProjectFullPath)))" Overwrite="true" />
  </Target>
  <Target Name="CicdRoslynBuildStarted" BeforeTargets="BeforeBuild">
    <PropertyGroup>
      <CicdRoslynBuildId>$([System.Guid]::NewGuid().ToString('N'))</CicdRoslynBuildId>
    </PropertyGroup>
    <MakeDir Directories="` + roslynOutDir + `" />
    <WriteLinesToFile File="` + roslynOutDir + `/$(CicdRoslynBuildId).started" Lines="$([MSBuild]::Escape($(MSBuildProjectFullPath)))" Overwrite="true" />
  </Target>
  <Target Name="CicdRoslynBuildDone" AfterTargets="Build">
    <WriteLinesToFile File="` + roslynOutDir + `/$(CicdRoslynBuildId).built" Lines="$(CicdRoslynBuildId)" Overwrite="true" />
  </Target>
</Project>
`

// roslynMarkerFailures names every project with a build instance that started
// and did not finish. started maps a marker id to the mount-relative project
// its .started file names ("" when it named a file outside the tree, which is
// ignored); built is the set of ids with a .built file. Sorted, each project
// once.
func roslynMarkerFailures(started map[string]string, built map[string]bool) []string {
	failed := map[string]bool{}
	for id, project := range started {
		if project != "" && !built[id] {
			failed[project] = true
		}
	}
	return sortedKeys(failed)
}

// roslynScriptPrologue starts both build scripts: the log directory, and
// every status file Go reads, created if missing and never truncated. The
// combined build runs on a fresh container; the per-project builds run after
// it, appending, or alone on a fresh one when its container did not complete.
var roslynScriptPrologue = "mkdir -p " + roslynOutDir + "\n" +
	": >> " + roslynFailedPath + "\n" +
	": >> " + roslynOutPath + "\n" +
	": >> " + roslynErrPath + "\n"

// roslynFastScript renders the combined build: one parallel MSBuild call over
// the generated solution (roslynSolution), so each project is evaluated and
// compiled once, in dependency order, on every core — instead of one cold
// build per project that re-evaluates its whole reference graph.
//
// The command line is fixed text: the solution's path is a cicd constant and
// the project paths are inside the file Go wrote, never in shell source
// (TestRoslynFastScriptIsFixedText). It reads /dev/null and always exits 0:
// the build's exit status says nothing per project, and Go reads the logs and
// the build markers instead. Whatever it left un-analysed is built again by
// roslynFallbackScript.
func roslynFastScript() string {
	return roslynScriptPrologue +
		"dotnet build " + roslynSolutionPath + " -m " + strings.Join(roslynBuildArgs, " ") +
		" </dev/null >>" + roslynOutPath + " 2>>" + roslynErrPath + "\n" +
		"exit 0"
}

// roslynFallbackScript renders the per-project builds the combined build
// could not stand in for: each project the fast path left un-analysed
// (roslynFallback), built on its own.
//
// The project list is written by Go to roslynProjectsPath and read line by
// line into a quoted "$p": a project path is consumer-controlled and is an
// argument here, never shell source. The fixed arguments are cicd constants
// (TestRoslynScriptIsShellSafe). Each project is built on its own so each has
// its own exit status, and every failure is written down by name; the script
// always exits 0 and Go classifies. It appends to the status files, so the
// combined build's console is not lost.
//
// Each build reads /dev/null, not the loop's stdin: the loop's stdin is the
// project list, and a credential provider or MSBuild node that reads stdin
// would swallow the projects after it, which would then be neither built nor
// named as failed.
func roslynFallbackScript() string {
	return roslynScriptPrologue +
		"while IFS= read -r p; do\n" +
		"  [ -n \"$p\" ] || continue\n" +
		"  if ! dotnet build \"$p\" " + strings.Join(roslynBuildArgs, " ") +
		" </dev/null >>" + roslynOutPath + " 2>>" + roslynErrPath + "; then\n" +
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

// Project-type ids a classic solution file names each entry by. The SDK picks
// the build from the project file itself; the id only has to be one MSBuild's
// solution parser recognises as a buildable project.
const (
	roslynCSharpProjectType = "{9A19103F-16F7-4668-BE54-9A1E7A4F7556}"
	roslynVBProjectType     = "{778DAE3C-4631-46EA-AA77-85C1314464D9}"
)

// roslynSolution renders the solution the fast path builds: every project in
// one file, so one parallel MSBuild invocation builds each project once and in
// dependency order, instead of one cold build per project.
//
// The classic format, not .slnx: the 8.0 SDK band cicd pins cannot read
// .slnx. The file lives outside the scanned tree, so the consumer's own
// Directory.Solution.props/targets do not apply, as they did not to the
// per-project builds. Paths are absolute container paths written by Go; the
// shell only ever sees the solution's fixed path.
//
// A path a solution entry cannot quote (a double quote, or a line break) is
// not written and is returned in unlisted, so it can still be built on its
// own. Every project is either in the solution or in unlisted.
func roslynSolution(projects []string) (sln string, unlisted []string) {
	type entry struct{ guid, kind, name, path string }
	var entries []entry
	for _, p := range projects {
		if strings.ContainsAny(p, "\"\r\n") {
			unlisted = append(unlisted, p)
			continue
		}
		kind := roslynCSharpProjectType
		if strings.HasSuffix(strings.ToLower(p), ".vbproj") {
			kind = roslynVBProjectType
		}
		base := p[strings.LastIndex(p, "/")+1:]
		if i := strings.LastIndex(base, "."); i > 0 {
			base = base[:i]
		}
		// MSBuild refuses a solution with two entries of one name (MSB5004),
		// and a monorepo has a Tests.csproj in many folders: the name carries
		// the start of the entry's path-derived id, so each is its own.
		guid := roslynProjectGUID(p)
		entries = append(entries, entry{guid, kind, base + "-" + guid[1:9], roslynMount + "/" + p})
	}

	var b strings.Builder
	b.WriteString("\nMicrosoft Visual Studio Solution File, Format Version 12.00\n")
	b.WriteString("# Visual Studio Version 17\n")
	b.WriteString("VisualStudioVersion = 17.0.31903.59\n")
	b.WriteString("MinimumVisualStudioVersion = 10.0.40219.1\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "Project(\"%s\") = \"%s\", \"%s\", \"%s\"\nEndProject\n", e.kind, e.name, e.path, e.guid)
	}
	b.WriteString("Global\n")
	b.WriteString("\tGlobalSection(SolutionConfigurationPlatforms) = preSolution\n")
	b.WriteString("\t\tDebug|Any CPU = Debug|Any CPU\n")
	b.WriteString("\tEndGlobalSection\n")
	b.WriteString("\tGlobalSection(ProjectConfigurationPlatforms) = postSolution\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "\t\t%s.Debug|Any CPU.ActiveCfg = Debug|Any CPU\n", e.guid)
		fmt.Fprintf(&b, "\t\t%s.Debug|Any CPU.Build.0 = Debug|Any CPU\n", e.guid)
	}
	b.WriteString("\tEndGlobalSection\n")
	b.WriteString("EndGlobal\n")
	return b.String(), unlisted
}

// roslynProjectGUID is a solution entry's project id: derived from the
// mount-relative path, so the same tree renders the same solution.
func roslynProjectGUID(path string) string {
	h := sha256.Sum256([]byte(path))
	return strings.ToUpper(fmt.Sprintf("{%x-%x-%x-%x-%x}", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]))
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
	// Failed is every project whose build did not succeed, mount-relative:
	// read from the build markers, and from the exit status of each
	// per-project build the fallback ran.
	Failed []string
	// Fallback is every project the combined build left un-analysed and that
	// was then built on its own, mount-relative. Empty when none was.
	Fallback []string
	// FastFailed is why the combined build's container could not be read,
	// "" when it could (or never ran). When set, Fallback is every project.
	FastFailed string
	// Unlisted is every project the solution could not name, so never in the
	// combined build; each is also in Fallback.
	Unlisted []string
	// Output is the build's console (errors only) and Stderr its stderr.
	Output, Stderr string
	Logs           []roslynLog
}

// roslynAnalysedProjects is the one answer to "was this project analysed":
// a project in build is analysed when a log attributed to it parses and has a
// run with at least one security rule switched on. The fallback selection and
// the verdict both ask it here, so they cannot disagree about which projects
// were reached.
func roslynAnalysedProjects(build []string, logs []roslynLog) map[string]bool {
	inBuild := setOf(build)
	analysed := map[string]bool{}
	for _, log := range logs {
		if !inBuild[log.Project] || analysed[log.Project] {
			continue
		}
		var doc roslynDoc
		if json.Unmarshal(log.SARIF, &doc) != nil {
			continue
		}
		for _, run := range doc.Runs {
			if on, _ := run.securityRules(); len(on) > 0 {
				analysed[log.Project] = true
				break
			}
		}
	}
	return analysed
}

// roslynFastResult is what the combined build left, read back before any
// per-project build runs.
type roslynFastResult struct {
	// Err is set when the combined build's container could not be read; the
	// fields below are then empty.
	Err error
	// Logs are its compiler logs; Started its .started markers (id →
	// project); Failed the projects with a build instance that started and
	// did not finish in it (roslynMarkerFailures).
	Logs    []roslynLog
	Started map[string]string
	Failed  []string
}

// roslynFastNeeded says the combined build has something to build: at least
// one project the solution could name.
func roslynFastNeeded(build, unlisted []string) bool {
	return len(unlisted) < len(build)
}

// roslynFallback is every project that gets a build of its own after the
// combined build, sorted, each once. Uncapped: a slower run that analyses
// every project is the point.
//
//   - Every project, when the combined build's container could not be read
//     (or there was none): nothing is known about any of them.
//   - Otherwise each one the combined build left un-analysed (the verdict's
//     own predicate), each one whose build failed inside it — the failure may
//     belong to the combined call alone (a parallel race, a dead node, a
//     build step that reads $(SolutionDir)), and the old loop built it alone
//     — and each one the solution could not name (unlisted).
func roslynFallback(build, unlisted []string, fast roslynFastResult) []string {
	if !roslynFastNeeded(build, unlisted) || fast.Err != nil {
		return sortedKeys(setOf(build))
	}
	analysed := roslynAnalysedProjects(build, fast.Logs)
	failed := setOf(fast.Failed)
	// Unlisted explicitly: compiled as another project's reference, it could
	// otherwise read as analysed without ever having been built as itself.
	retry := setOf(unlisted)
	for _, p := range build {
		if !analysed[p] || failed[p] {
			retry[p] = true
		}
	}
	return sortedKeys(retry)
}

// roslynFailures is the final Failed list: every project whose build did not
// succeed, each judged by its last build. fast.Started holds the .started
// markers the combined build wrote, started and built every marker after the
// per-project builds, failedFile the per-project builds' failures by exit
// status, retried the projects those builds rebuilt. A retried project is
// judged by its own build alone; one not retried keeps the combined build's
// verdict.
func roslynFailures(fast roslynFastResult, started map[string]string, built map[string]bool, failedFile, retried []string) []string {
	wasRetried := setOf(retried)
	later := map[string]string{}
	for id, p := range started {
		if _, inFast := fast.Started[id]; !inFast {
			later[id] = p
		}
	}
	failed := setOf(failedFile)
	for _, p := range roslynMarkerFailures(fast.Started, built) {
		if !wasRetried[p] {
			failed[p] = true
		}
	}
	for _, p := range roslynMarkerFailures(later, built) {
		failed[p] = true
	}
	return sortedKeys(failed)
}

// setOf is the set of items.
func setOf(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}

// roslynFastFailedWarning says the combined build's container did not
// complete, so its logs could not be read and every project was built on its
// own instead: the slowest path, and the reason for it.
func roslynFastFailedWarning(reason string) string {
	return fmt.Sprintf("%s: the combined build did not complete (%s); every project was built one at a time "+
		"instead", roslynToolName, roslynTrimMount(firstLine(reason)))
}

// roslynFallbackWarnings say the run needed the per-project builds, and for
// which projects: the slow path, disclosed so a slow run explains itself. A
// project the solution could not name (unlisted) was never in the combined
// build, so it is named on its own and counted on neither side of "left N of
// M"; listed is the number of projects the combined build was asked to build.
func roslynFallbackWarnings(fallback, unlisted []string, listed int) []string {
	isUnlisted := setOf(unlisted)
	var left []string
	for _, p := range fallback {
		if !isUnlisted[p] {
			left = append(left, p)
		}
	}
	var w []string
	if len(left) > 0 {
		w = append(w, fmt.Sprintf("%s: the combined build left %d of %d C#/VB projects without an analyzer log or "+
			"a clean build; they were rebuilt one at a time: %s", roslynToolName, len(left), listed,
			strings.Join(firstN(left, roslynExamplesShown), ", ")))
	}
	if len(unlisted) > 0 {
		w = append(w, fmt.Sprintf("%s: %d C#/VB %s could not be listed in the generated solution and %s built "+
			"one at a time: %s", roslynToolName, len(unlisted), pick(len(unlisted), "project", "projects"),
			pick(len(unlisted), "was", "were"), strings.Join(firstN(unlisted, roslynExamplesShown), ", ")))
	}
	return w
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

// roslynFeedWarning names a feed URL that arrived without its token. The
// credential config is written only for the pair, so the URL alone changes
// nothing: the restore uses the repository's own NuGet configuration, and a
// feed that needs authentication fails there as an unbuildable project whose
// log names a 401, not the missing token.
func roslynFeedWarning(feedURL string, hasToken bool) string {
	if feedURL == "" || hasToken {
		return ""
	}
	return roslynToolName + ": nuget-feed-url was given without nuget-token, so no credential was configured " +
		"for it; the restore used the repository's own NuGet configuration, and a project that needs that feed " +
		"authenticated reads as unbuildable"
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
	if out.FastFailed != "" {
		res.Warnings = append(res.Warnings, roslynFastFailedWarning(out.FastFailed))
	} else {
		res.Warnings = append(res.Warnings, roslynFallbackWarnings(out.Fallback, out.Unlisted, len(s.Build)-len(out.Unlisted))...)
	}

	failed := setOf(out.Failed)
	inBuild := setOf(s.Build)

	type kept struct {
		result roslynDocResult
		key    string
	}
	var (
		results    []kept
		seen       = map[string]bool{}
		rulesOn    = map[string]roslynDocRule{}
		offIn      = map[string]map[string]bool{} // rule → projects that switched it off
		analysed   = roslynAnalysedProjects(s.Build, out.Logs)
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
