//go:build unit_test

package main

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture logs below have the shape the pinned SDK's compiler writes
// (SARIF 2.1, driver "Microsoft (R) Visual C# Compiler", one run per compile,
// every loaded rule in driver.rules, repository configuration as invocation
// overrides, pragma suppressions as kind inSource with no status), cut down to
// the fields the leg reads. File and type names are neutral stand-ins.

const sdkProject = `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFrameworks>net8.0;net10.0</TargetFrameworks></PropertyGroup>
</Project>`

type fixtureRule struct {
	id, category string
	off          bool // switched off by the repository (an invocation override)
}

type fixtureResult struct {
	rule, level, uri, msg string
	line                  int
	suppressed            bool
}

func compilerLog(t *testing.T, rules []fixtureRule, results []fixtureResult) []byte {
	t.Helper()
	var descs, overrides, out []any
	for i, r := range rules {
		descs = append(descs, map[string]any{
			"id":               r.id,
			"shortDescription": map[string]any{"text": "description of " + r.id},
			"helpUri":          "https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/" + strings.ToLower(r.id),
			"properties":       map[string]any{"category": r.category, "executionTimeInSeconds": "0.01"},
		})
		if r.off {
			overrides = append(overrides, map[string]any{
				"descriptor":    map[string]any{"id": r.id, "index": i},
				"configuration": map[string]any{"enabled": false},
			})
		}
	}
	for _, r := range results {
		res := map[string]any{
			"ruleId":  r.rule,
			"level":   r.level,
			"message": map[string]any{"text": r.msg},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": r.uri},
				"region":           map[string]any{"startLine": r.line, "startColumn": 9, "endLine": r.line, "endColumn": 40},
			}}},
			"relatedLocations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": "file:///src/web/Other.cs"},
			}}},
			"properties": map[string]any{"warningLevel": 1},
		}
		if r.suppressed {
			res["suppressions"] = []any{map[string]any{"kind": "inSource", "properties": map[string]any{"suppressionType": "Pragma Directive"}}}
		}
		out = append(out, res)
	}
	doc := map[string]any{
		"$schema": "http://json.schemastore.org/sarif-2.1.0",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Microsoft (R) Visual C# Compiler", "semanticVersion": "5.9.0", "rules": descs,
			}},
			"invocations": []any{map[string]any{"executionSuccessful": true, "ruleConfigurationOverrides": overrides}},
			"results":     out,
			"properties":  map[string]any{"analyzerExecutionTime": "1.234"},
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var fixtureRules = []fixtureRule{
	{id: "CA2100", category: "Security"},
	{id: "CA3001", category: "Security"},
	{id: "CA5350", category: "Security"},
	{id: "CA5351", category: "Security", off: true},
	{id: "CA1822", category: "Performance"},
}

func fixtureResults() []fixtureResult {
	return []fixtureResult{
		{rule: "CA3001", level: "warning", uri: "file:///src/web/OrderController.cs", line: 12, msg: "Potential SQL injection via 'id'"},
		{rule: "CA2100", level: "warning", uri: "file:///src/web/OrderController.cs", line: 12, msg: "Review SQL query for security vulnerabilities"},
		{rule: "CA5350", level: "note", uri: "file:///src/web/Hashing.cs", line: 7, msg: "SHA1 uses a weak algorithm"},
		{rule: "CA5350", level: "note", uri: "file:///src/web/Hashing.cs", line: 15, msg: "SHA1 uses a weak algorithm", suppressed: true},
		{rule: "CA1822", level: "note", uri: "file:///src/web/Hashing.cs", line: 3, msg: "Member can be static"},
		{rule: "CA5350", level: "note", uri: "file:///src/web/obj/Debug/net8.0/Generated.cs", line: 1, msg: "SHA1 in generated code"},
		{rule: "CA5350", level: "note", uri: "file:///root/.nuget/packages/some.package/1.0.0/Source.cs", line: 1, msg: "SHA1 in package source"},
	}
}

// TestRoslynClassifiesWhatItCanBuild: every project is either built, named
// as uncovered with the reason, or named as F#. Nothing is dropped.
func TestRoslynClassifiesWhatItCanBuild(t *testing.T) {
	s := classifyRoslynProjects(map[string]string{
		"web/Web.csproj":           sdkProject,
		"lib/Lib.vbproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`,
		"imported/Imported.csproj": `<Project><Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" /></Project>`,
		"element/Element.csproj":   `<Project><Sdk Name="Microsoft.NET.Sdk" /></Project>`,
		"dynamic/Dynamic.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>$(AppTargets)</TargetFrameworks></PropertyGroup></Project>`,
		"mixed/Mixed.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net8.0;net8.0-android</TargetFrameworks></PropertyGroup></Project>`,
		"desktop/Desktop.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0-windows</TargetFramework><UseWPF>true</UseWPF></PropertyGroup></Project>`,
		"legacy/Legacy.csproj":     `<?xml version="1.0"?><Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /></Project>`,
		"app/App.csproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><UseMaui>true</UseMaui><TargetFrameworks>net8.0-ios</TargetFrameworks></PropertyGroup></Project>`,
		"phone/Phone.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net8.0-android;net8.0-ios</TargetFrameworks></PropertyGroup></Project>`,
		"odd\nname/Odd.csproj":     sdkProject,
		"fn/Pricing.fsproj":        `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
	})
	want := []string{"desktop/Desktop.csproj", "dynamic/Dynamic.csproj", "element/Element.csproj", "imported/Imported.csproj", "lib/Lib.vbproj", "mixed/Mixed.csproj", "web/Web.csproj"}
	if strings.Join(s.Build, ",") != strings.Join(want, ",") {
		t.Errorf("Build = %v, want %v", s.Build, want)
	}
	reasons := map[string]string{}
	for _, u := range s.Uncovered {
		reasons[u.Path] = u.Reason
	}
	for path, fragment := range map[string]string{
		"legacy/Legacy.csproj": "legacy (non-SDK)",
		"app/App.csproj":       "MAUI",
		"phone/Phone.csproj":   "net8.0-android;net8.0-ios",
		"odd\nname/Odd.csproj": "line break",
	} {
		if !strings.Contains(reasons[path], fragment) {
			t.Errorf("%q: reason %q, want it to mention %q", path, reasons[path], fragment)
		}
	}
	if len(s.Uncovered) != 4 {
		t.Errorf("Uncovered = %+v", s.Uncovered)
	}
	if strings.Join(s.FSharp, ",") != "fn/Pricing.fsproj" {
		t.Errorf("FSharp = %v", s.FSharp)
	}
	if s.total() != 11 {
		t.Errorf("total = %d: the denominator is every C#/VB project, buildable or not, and never F#", s.total())
	}
}

// TestRoslynSeverityTableBoundaries pins cicd's own grade: the consumer's
// configured level never decides it, and the range edges are exact.
func TestRoslynSeverityTableBoundaries(t *testing.T) {
	for id, want := range map[string]Severity{
		"CA3001": SeverityHigh, "CA3007": SeverityHigh, "CA3012": SeverityHigh, "CA3013": SeverityMedium,
		"CA2299": SeverityMedium, "CA2300": SeverityHigh, "CA2330": SeverityHigh, "CA2331": SeverityMedium,
		"CA2349": SeverityMedium, "CA2350": SeverityHigh, "CA2362": SeverityHigh, "CA2363": SeverityMedium,
		"CA5359": SeverityHigh, "CA5360": SeverityHigh, "CA5361": SeverityMedium,
		"CA5350": SeverityMedium, "CA5351": SeverityMedium, "CA2100": SeverityMedium,
		"CA30010": SeverityMedium, "CA300": SeverityMedium, "ca3001": SeverityMedium, "": SeverityMedium,
	} {
		if got := roslynSeverity(id); got != want {
			t.Errorf("roslynSeverity(%q) = %s, want %s", id, got, want)
		}
	}
}

// TestRoslynProjectsTheSecurityFindingsOnce is the main path: two compiles of
// one multi-targeted project, read as one analysed project, deduplicated,
// security-only, graded by cicd, paths relative, nothing absolute left.
func TestRoslynProjectsTheSecurityFindingsOnce(t *testing.T) {
	s := classifyRoslynProjects(map[string]string{"web/Web.csproj": sdkProject})
	log := compilerLog(t, fixtureRules, fixtureResults())
	r := analyseRoslyn(s, roslynOutcome{Band: "10.0", Logs: []roslynLog{
		{Project: "web/Web.csproj", SARIF: log},
		{Project: "web/Web.csproj", SARIF: log},
	}})
	if r.Err != nil || !r.Present || r.Skipped {
		t.Fatalf("result = %+v", r)
	}
	if *r.Examined != (Examined{Unit: "C#/VB projects", Count: 1, Total: 1}) {
		t.Errorf("Examined = %+v", *r.Examined)
	}
	if got := r.BySeverity; got[SeverityHigh] != 1 || got[SeverityMedium] != 2 || len(got) != 2 {
		t.Errorf("BySeverity = %v, want 1 HIGH (CA3001) and 2 MEDIUM (CA2100, CA5350); the suppressed, non-security and outside-tree results are not counted", got)
	}
	if got := parseSarifSeverities(r.SARIF); got[SeverityHigh] != r.BySeverity[SeverityHigh] || got[SeverityMedium] != r.BySeverity[SeverityMedium] {
		t.Errorf("the SARIF reads %v and the row counts %v: a reader of the document must reach the row's grade", got, r.BySeverity)
	}
	if r.Rules == nil || r.Rules.Count != 3 || !strings.Contains(r.Rules.Pinned, "mcr.microsoft.com/dotnet/sdk:10.0") {
		t.Errorf("Rules = %+v, want the 3 security rules that ran, pinned to the SDK image", r.Rules)
	}

	body := string(r.SARIF)
	for _, absent := range []string{"file://", "/src/", "/root/", "Microsoft (R)", "relatedLocations", "ruleIndex", "invocations", "CA1822", "CA5351", "warningLevel", "Pragma Directive"} {
		if strings.Contains(body, absent) {
			t.Errorf("projected SARIF carries %q:\n%s", absent, body)
		}
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID     string `json:"id"`
						Config struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Automation struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(r.SARIF, &doc); err != nil || len(doc.Runs) != 1 {
		t.Fatalf("projected SARIF: %v / %s", err, body)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != roslynToolName || run.Automation.ID != roslynToolName {
		t.Errorf("driver %q, automation %q: the finding joins to its row by the row's name", run.Tool.Driver.Name, run.Automation.ID)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4 (two compiles deduplicated, suppressed one kept and marked)", len(run.Results))
	}
	levels := map[string]string{}
	for _, res := range run.Results {
		levels[res.RuleID] = res.Level
		if u := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; !strings.HasPrefix(u, "web/") {
			t.Errorf("%s at %q: want a path relative to the scanned tree", res.RuleID, u)
		}
	}
	if levels["CA3001"] != "error" || levels["CA2100"] != "warning" || levels["CA5350"] != "warning" {
		t.Errorf("levels = %v: the compiler said warning/note, cicd's table says error for CA3001 and warning for the rest", levels)
	}
	for _, rule := range run.Tool.Driver.Rules {
		if want := roslynLevel(roslynSeverity(rule.ID)); rule.Config.Level != want {
			t.Errorf("rule %s defaultConfiguration.level = %q, want %q", rule.ID, rule.Config.Level, want)
		}
	}

	joined := strings.Join(r.Warnings, "\n")
	for _, want := range []string{
		"NARROWED RULES — 1 security rule was switched off by the repository's own configuration",
		"CA5351 (1)",
		"roslyn-analyzers: 1 finding suppressed in source",
		"2 findings outside the scanned tree",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "PARTIAL") || strings.Contains(joined, "not analysed") {
		t.Errorf("a clean, complete build must not read as partial:\n%s", joined)
	}
}

// TestRoslynCompileErrorsMakeTheScanPartial: a project the compiler analysed
// over a broken program, or whose build failed after its log was written, is
// counted and named as partial — a floor, not a verdict.
func TestRoslynCompileErrorsMakeTheScanPartial(t *testing.T) {
	s := classifyRoslynProjects(map[string]string{"web/Web.csproj": sdkProject, "api/Api.csproj": sdkProject})
	broken := append(fixtureResults(), fixtureResult{rule: "CS0103", level: "error", uri: "file:///src/web/Broken.cs", line: 4, msg: "The name 'x' does not exist"})
	r := analyseRoslyn(s, roslynOutcome{
		Failed: []string{"web/Web.csproj", "api/Api.csproj"},
		Logs: []roslynLog{
			{Project: "web/Web.csproj", SARIF: compilerLog(t, fixtureRules, broken)},
			{Project: "api/Api.csproj", SARIF: compilerLog(t, fixtureRules, nil)},
		},
	})
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if r.Examined.Count != 2 || r.Examined.Partial != 2 {
		t.Errorf("Examined = %+v, want both analysed and both partial (one compile error, one failed build)", *r.Examined)
	}
	joined := strings.Join(r.Warnings, "\n")
	if !strings.Contains(joined, "PARTIAL SCAN — 2 analysed projects") || !strings.Contains(joined, "api/Api.csproj, web/Web.csproj") {
		t.Errorf("warnings:\n%s", joined)
	}
	if strings.Contains(string(r.SARIF), "CS0103") {
		t.Error("a compiler error is a partial-scan signal, not a security finding")
	}
}

// TestRoslynANonRunIsAnError: projects to build and not one analyzer log —
// the build died, analysis was off, or the log went elsewhere — is a SAST
// non-run, with the first build error named, never a clean row.
func TestRoslynANonRunIsAnError(t *testing.T) {
	s := classifyRoslynProjects(map[string]string{"web/Web.csproj": sdkProject})
	noSecurity := compilerLog(t, []fixtureRule{{id: "CA1822", category: "Performance"}}, nil)
	for name, out := range map[string]roslynOutcome{
		"no logs": {
			Failed: []string{"web/Web.csproj"},
			Output: "  Determining projects to restore...\n/src/web/Web.csproj : error NU1301: Unable to load the service index for source https://feed.example.com/v3/index.json.\n",
		},
		"analysis off": {Logs: []roslynLog{{Project: "web/Web.csproj", SARIF: noSecurity}}},
		"unparsable":   {Logs: []roslynLog{{Project: "web/Web.csproj", SARIF: []byte("{not json")}}},
		"unattributed": {Logs: []roslynLog{{Project: "", SARIF: compilerLog(t, fixtureRules, nil)}}},
	} {
		r := analyseRoslyn(s, out)
		if r.Err == nil || !strings.Contains(r.Err.Error(), "SAST did not run") {
			t.Errorf("%s: want a non-run, got %+v", name, r)
			continue
		}
		if r.Examined == nil || r.Examined.Count != 0 || r.Examined.Total != 1 {
			t.Errorf("%s: Examined = %+v", name, r.Examined)
		}
		if r.SARIF != nil || r.BySeverity != nil {
			t.Errorf("%s: a non-run carries no findings document or counts", name)
		}
	}
	r := analyseRoslyn(s, roslynOutcome{Output: "/src/web/Web.csproj : error NU1301: Unable to load the service index\n"})
	if !strings.Contains(r.Err.Error(), "first build error: web/Web.csproj : error NU1301") {
		t.Errorf("the diagnosis names the consumer's path, not the container's: %v", r.Err)
	}
}

// TestRoslynNamesTheProjectsItDidNotReach: one of two analysed reads short,
// named, beside the uncovered and F# projects that were never built.
func TestRoslynNamesTheProjectsItDidNotReach(t *testing.T) {
	s := classifyRoslynProjects(map[string]string{
		"web/Web.csproj":       sdkProject,
		"api/Api.csproj":       sdkProject,
		"legacy/Legacy.csproj": `<Project ToolsVersion="15.0"></Project>`,
		"fn/Pricing.fsproj":    sdkProject,
	})
	r := analyseRoslyn(s, roslynOutcome{
		Failed:   []string{"api/Api.csproj"},
		Output:   "/src/api/Api.csproj : error MSB4019: The imported project was not found.\n",
		BandNote: "global.json pins SDK 9.0.100; analysed with the 10.0 band",
		Logs:     []roslynLog{{Project: "web/Web.csproj", SARIF: compilerLog(t, fixtureRules, nil)}},
	})
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if *r.Examined != (Examined{Unit: "C#/VB projects", Count: 1, Total: 3}) {
		t.Errorf("Examined = %+v: the short count is the gap's only number on the row", *r.Examined)
	}
	joined := strings.Join(r.Warnings, "\n")
	for _, want := range []string{
		"1 of 3 C#/VB projects was not analysed",
		"api/Api.csproj (first build error: api/Api.csproj : error MSB4019",
		"legacy/Legacy.csproj (legacy (non-SDK)",
		"1 F# project is not covered",
		"fn/Pricing.fsproj",
		"roslyn-analyzers: global.json pins SDK 9.0.100",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q:\n%s", want, joined)
		}
	}
}

// TestRoslynWithNothingToBuildSaysSo: no .NET at all is no row; .NET that
// cicd cannot build is a skipped row naming why, never a clean zero and
// never a red the consumer cannot clear.
func TestRoslynWithNothingToBuildSaysSo(t *testing.T) {
	if r := roslynScopeOnly(classifyRoslynProjects(nil)); r.Present {
		t.Errorf("no .NET project must leave no row: %+v", r)
	}
	for name, tree := range map[string]map[string]string{
		"F# only":     {"fn/Pricing.fsproj": sdkProject},
		"legacy only": {"legacy/Legacy.csproj": `<Project ToolsVersion="4.0"></Project>`},
	} {
		s := classifyRoslynProjects(tree)
		r := roslynScopeOnly(s)
		if !r.Present || !r.Skipped || r.Err != nil {
			t.Errorf("%s: want a present, skipped row, got %+v", name, r)
		}
		if r.Examined.Count != 0 || r.Examined.Total != s.total() {
			t.Errorf("%s: Examined = %+v", name, *r.Examined)
		}
		if j := strings.Join(r.Warnings, "\n"); !strings.Contains(j, "SKIPPED") || !strings.Contains(j, "CA3001–CA3012") {
			t.Errorf("%s: warnings:\n%s", name, j)
		}
	}
}

// TestRoslynURIsStayInsideTheTree: only a file under the scan mount is the
// consumer's source; anything else, traversal included, is dropped.
func TestRoslynURIsStayInsideTheTree(t *testing.T) {
	for uri, want := range map[string]string{
		"file:///src/web/OrderController.cs": "web/OrderController.cs",
		"file:///src/a/b/c.cs":               "a/b/c.cs",
		"file:///src/":                       "",
		"file:///src/../etc/passwd":          "",
		"file:///src/web/../../etc/passwd":   "",
		"file:///src/web/obj/Debug/G.cs":     "",
		"file:///src/web/bin/Debug/G.cs":     "",
		"file:///src/robj/A.cs":              "robj/A.cs",
		"file:///srcx/web/A.cs":              "",
		"file:///root/.nuget/packages/x.cs":  "",
		"/src/web/A.cs":                      "",
	} {
		got, ok := roslynRelativeURI(uri)
		if got != want || ok != (want != "") {
			t.Errorf("roslynRelativeURI(%q) = %q, %v; want %q", uri, got, ok, want)
		}
	}
	if got := roslynSidecarProject("/src/web/Web.csproj\n"); got != "web/Web.csproj" {
		t.Errorf("sidecar = %q", got)
	}
	if got := roslynSidecarProject("/tmp/elsewhere/Web.csproj"); got != "" {
		t.Errorf("a sidecar outside the mount attributes to no project, got %q", got)
	}
}

// TestRoslynTargetsIsWellFormed: a targets file MSBuild cannot parse fails
// every build — loudly, but for every consumer at once.
func TestRoslynTargetsIsWellFormed(t *testing.T) {
	var v struct {
		XMLName xml.Name
		Target  struct {
			Name          string `xml:"Name,attr"`
			BeforeTargets string `xml:"BeforeTargets,attr"`
		}
	}
	if err := xml.Unmarshal([]byte(roslynTargets), &v); err != nil {
		t.Fatal(err)
	}
	if v.XMLName.Local != "Project" || v.Target.BeforeTargets != "CoreCompile" {
		t.Errorf("targets = %+v", v)
	}
	for _, want := range []string{roslynOutDir + "/$(CicdRoslynLogId).sarif,version=2.1", "$(MSBuildProjectFullPath)"} {
		if !strings.Contains(roslynTargets, want) {
			t.Errorf("targets lacks %q", want)
		}
	}
	if !strings.Contains(strings.Join(roslynBuildArgs, " "), "CustomAfterMicrosoftCommonTargets="+roslynTargetsPath) {
		t.Error("the build does not import the targets file")
	}
}

// TestRoslynScriptIsShellSafe drives the real script with a stub dotnet:
// project paths are arguments, never source; every project is built on its
// own; each failure is written down by name; the script exits 0.
func TestRoslynScriptIsShellSafe(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	argLog := filepath.Join(dir, "args")
	// The stub drains stdin, as a credential provider or an MSBuild node
	// may: with the loop's stdin inherited, the first build would swallow
	// every project after it.
	stub := "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$2\" >> " + argLog + "\ncase \"$2\" in *Bad*) echo \"$2 : error CS0001: broken\"; exit 1;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "dotnet"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	script := roslynBuildScript()
	for _, p := range []string{roslynProjectsPath, roslynFailedPath, roslynOutPath, roslynErrPath, roslynDir} {
		script = strings.ReplaceAll(script, p, filepath.Join(dir, strings.TrimPrefix(p, "/")))
	}
	pwned := filepath.Join(dir, "pwned")
	projects := []string{"web/Web.csproj", "odd dir/$(touch " + pwned + ").csproj", "bad/Bad.csproj", "quote'/Q.csproj"}
	list := strings.ReplaceAll(roslynProjectsFile(projects), roslynMount+"/", dir+"/src/")
	listPath := filepath.Join(dir, strings.TrimPrefix(roslynProjectsPath, "/"))
	if err := os.MkdirAll(filepath.Dir(listPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("a project path was executed as shell source")
	}
	args, _ := os.ReadFile(argLog)
	if got := strings.Count(string(args), "\n"); got != len(projects) {
		t.Errorf("built %d times, want %d (one build per project):\n%s", got, len(projects), args)
	}
	if !strings.Contains(string(args), "$(touch "+pwned+").csproj") {
		t.Errorf("the hostile path did not reach dotnet as one argument:\n%s", args)
	}
	failed, _ := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(roslynFailedPath, "/")))
	if strings.TrimSpace(string(failed)) != dir+"/src/bad/Bad.csproj" {
		t.Errorf("failed = %q", failed)
	}
	out, _ := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(roslynOutPath, "/")))
	if !strings.Contains(string(out), "error CS0001") {
		t.Errorf("the build console is where MSBuild writes errors, and it was not kept: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, strings.TrimPrefix(roslynOutDir, "/"))); err != nil {
		t.Errorf("the log directory was not created: %v", err)
	}
}

func TestRoslynFeedWarning(t *testing.T) {
	if w := roslynFeedWarning("", false); w != "" {
		t.Errorf("no feed must say nothing, got %q", w)
	}
	if w := roslynFeedWarning("https://nuget.example.com/v3/index.json", true); w != "" {
		t.Errorf("a feed with its token must say nothing, got %q", w)
	}
	w := roslynFeedWarning("https://nuget.example.com/v3/index.json", false)
	if !strings.Contains(w, "without nuget-token") || !strings.HasPrefix(w, roslynToolName+": ") {
		t.Errorf("a feed without its token must be named: %q", w)
	}
}
