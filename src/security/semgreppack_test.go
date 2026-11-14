package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustPacks(t *testing.T) []semgrepPack {
	t.Helper()
	packs, err := loadSemgrepPacks()
	if err != nil {
		t.Fatalf("embedded manifests do not parse: %v", err)
	}
	return packs
}

func mustPack(t *testing.T, name string) semgrepPack {
	t.Helper()
	for _, p := range mustPacks(t) {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no pinned pack %s", name)
	return semgrepPack{}
}

func mustPlan(t *testing.T, rulesets string) semgrepPlan {
	t.Helper()
	plan, err := semgrepPlanFor(rulesets, mustPacks(t))
	if err != nil {
		t.Fatalf("semgrepPlanFor(%q): %v", rulesets, err)
	}
	return plan
}

// TestSemgrepPackManifestIsTheFrozenSet pins the numbers each manifest was
// measured at. A change here is a change to every consumer's rule set, and has
// to arrive with the spec's bump procedure, not as a side effect.
func TestSemgrepPackManifestIsTheFrozenSet(t *testing.T) {
	want := map[string][3]int{
		"p/security-audit": {724, 710, 23},
		"p/owasp-top-ten":  {559, 551, 22},
		"p/secrets":        {52, 52, 9},
	}
	packs := mustPacks(t)
	var names []string
	for _, p := range packs {
		names = append(names, p.Name)
		w, ok := want[p.Name]
		if !ok {
			t.Fatalf("unexpected pinned pack %s", p.Name)
		}
		if got := [3]int{len(p.IDs), len(p.Files), len(p.Tops)}; got != w {
			t.Errorf("%s = %d rules, %d files, %d top dirs; want %d, %d, %d", p.Name, got[0], got[1], got[2], w[0], w[1], w[2])
		}
		for _, id := range p.IDs {
			if id == strings.ToLower(semgrepGHACurlPipeRuleID) {
				t.Errorf("%s lists the parse-fragile upstream gha-curl-pipe-shell; cicd's embedded rule replaces it", p.Name)
			}
		}
	}
	if strings.Join(names, ",") != "p/security-audit,p/owasp-top-ten,p/secrets" {
		t.Fatalf("pinned packs = %v", names)
	}
	if !packs[0].GHAFallback || !packs[1].GHAFallback || packs[2].GHAFallback {
		t.Fatal("only the packs whose registry answer carried gha-curl-pipe-shell get the embedded rule")
	}
	if len(semgrepRulesCommit) != 40 || strings.Trim(semgrepRulesCommit, "0123456789abcdef") != "" {
		t.Fatalf("semgrepRulesCommit %q is not a full commit sha; a branch or tag can move", semgrepRulesCommit)
	}
}

// TestSemgrepPackCeilingHoldsByConstruction is what lets semgrepRuleSet skip a
// ceiling check. semgrep-security-audit.txt lists every rule its files hold
// (measured: the scan loads exactly 724 plus cicd's one), so if every other
// manifest's files are among its files, every rule a staged file brings is
// known to the plan, and the ones no requested pack names are excluded.
func TestSemgrepPackCeilingHoldsByConstruction(t *testing.T) {
	packs := mustPacks(t)
	audit := map[string]bool{}
	for _, f := range packs[0].Files {
		audit[f] = true
	}
	for _, p := range packs[1:] {
		for _, f := range p.Files {
			if !audit[f] {
				t.Errorf("%s stages %s, which semgrep-security-audit.txt does not list; its other rules are unknown to the plan", p.Name, f)
			}
		}
	}
}

func TestSemgrepPackRefusesWhatStagingCannotReproduce(t *testing.T) {
	cases := map[string]string{
		"no rows":           "# only a comment\n",
		"one field":         "bash/curl/security/curl-eval.yaml\n",
		"three fields":      "bash/a.yaml bash.a.x extra\n",
		"shell character":   "bash/$(id).yaml bash.$(id).x\n",
		"absolute":          "/bash/a.yaml bash.a.x\n",
		"parent traversal":  "bash/../a.yaml bash.a.x\n",
		"no language dir":   "a.yaml a.x\n",
		"not yaml":          "bash/a.json bash.a.x\n",
		"rule test fixture": "bash/a.test.yaml bash.a.test.x\n",
		"id from elsewhere": "bash/a.yaml python.a.x\n",
		"id is the prefix":  "bash/a.yaml bash.a.\n",
		"duplicate id":      "bash/a.yaml bash.a.x\nbash/a.yaml BASH.A.X\n",
		"reserved root":     "src/a.yaml src.a.x\n",
		"image root":        "usr/a.yaml usr.a.x\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if p, err := parseSemgrepPack(raw); err == nil {
				t.Fatalf("parseSemgrepPack accepted %q: %+v", raw, p)
			}
		})
	}

	p, err := parseSemgrepPack("# header\n\nbash/a/b.yml bash.a.b.x\nbash/a/b.yml bash.a.b.y\ngo/c.yaml Go.C.z\n")
	if err != nil {
		t.Fatalf("control rejected: %v", err)
	}
	if strings.Join(p.Files, ",") != "bash/a/b.yml,go/c.yaml" ||
		strings.Join(p.IDs, ",") != "bash.a.b.x,bash.a.b.y,go.c.z" ||
		strings.Join(p.Tops, ",") != "bash,go" {
		t.Fatalf("control parsed as %+v", p)
	}
}

// TestSemgrepPackStagingGivesTheRegistryID is the layout proof in miniature:
// a file staged as /<dir>/<stem>/<file> and loaded through --config /<top>
// gets the id <dir>.<stem>.<rule>, which is the registry's. The container
// measurement this rests on is in the spec.
func TestSemgrepPackStagingGivesTheRegistryID(t *testing.T) {
	p := mustPack(t, "p/security-audit")
	lines := strings.Split(strings.TrimSuffix(semgrepPackStaging(p.Files), "\n"), "\n")
	if len(lines) != len(p.Files) {
		t.Fatalf("staging lists %d files, manifest has %d", len(lines), len(p.Files))
	}
	for _, l := range lines {
		f, dest, ok := strings.Cut(l, " ")
		if !ok || strings.Contains(dest, " ") {
			t.Fatalf("staging line %q is not \"<path> <dir>\"", l)
		}
		if got, want := strings.ReplaceAll(strings.TrimPrefix(dest, "/"), "/", ".")+".", semgrepPackIDPrefix(f); got != want {
			t.Errorf("%s staged at %s derives prefix %q, want %q", f, dest, got, want)
		}
	}
	if !strings.Contains(semgrepPackStaging(p.Files), "bash/curl/security/curl-eval.yaml /bash/curl/security/curl-eval\n") {
		t.Error("the known row bash/curl/security/curl-eval.yaml is not staged at /bash/curl/security/curl-eval")
	}
}

func TestSemgrepPlanInterceptsThePinnedPack(t *testing.T) {
	p := mustPack(t, "p/security-audit")

	plan := mustPlan(t, defaultSastRulesets)
	if strings.Join(plan.Pinned, ",") != "p/security-audit" || len(plan.Live) != 0 || len(plan.Excluded) != 0 {
		t.Fatalf("default plan = %+v, want security-audit pinned, nothing live, nothing excluded", plan)
	}
	var want []string
	for _, top := range p.Tops {
		want = append(want, "--config", "/"+top)
	}
	want = append(want, "--config", semgrepGHAFallbackPath, "--config", semgrepDOMRulePath)
	if strings.Join(plan.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("default args = %v, want %v", plan.Args, want)
	}
	for _, d := range semgrepPinnedPackDefs() {
		if strings.Contains(strings.Join(plan.Args, " "), d.Name) {
			t.Fatalf("pinned pack %s still reaches semgrep as a registry id", d.Name)
		}
	}
	if len(plan.Floor) != 724 || len(plan.Files) != 710 {
		t.Fatalf("default floor/files = %d/%d, want 724/710", len(plan.Floor), len(plan.Files))
	}

	twice := mustPlan(t, "p/security-audit, p/security-audit")
	if strings.Join(twice.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("naming the pack twice staged it twice: %v", twice.Args)
	}

	// Every owasp rule is a security-audit rule, so naming both stages the
	// same tree with the same floor, once, in table order whatever the
	// caller's order.
	both := mustPlan(t, "p/owasp-top-ten,p/security-audit")
	if strings.Join(both.Pinned, ",") != "p/security-audit,p/owasp-top-ten" ||
		strings.Join(both.Args, " ") != strings.Join(want, " ") || len(both.Floor) != 724 || len(both.Excluded) != 0 {
		t.Fatalf("security-audit + owasp plan = %+v", both)
	}

	mixed := mustPlan(t, "p/python,p/security-audit,./semgrep.yml,r/python.lang.x")
	if strings.Join(mixed.Pinned, ",") != "p/security-audit" || strings.Join(mixed.Live, ",") != "p/python,r/python.lang.x" {
		t.Fatalf("mixed plan = %+v", mixed)
	}
	if mixed.Args[1] != "p/python" || !strings.Contains(strings.Join(mixed.Args, " "), "--config ./semgrep.yml") {
		t.Fatalf("mixed plan lost a caller config or its order: %v", mixed.Args)
	}

	live := mustPlan(t, "p/python")
	if len(live.Pinned) != 0 || strings.Join(live.Args, " ") != "--config p/python" || live.Files != nil {
		t.Fatalf("a plan without a pinned pack = %+v", live)
	}

	for _, refused := range []string{"auto", "", "p/x;id"} {
		if _, err := semgrepPlanFor(refused, mustPacks(t)); err == nil {
			t.Errorf("semgrepPlanFor(%q) accepted what semgrepConfigFlags refuses", refused)
		}
	}
}

// pickleRules are the three rules the owasp files carry that p/owasp-top-ten
// does not include (measured against the 2026-10-24 capture).
var pickleRules = []string{
	"python.lang.security.deserialization.pickle.avoid-cPickle",
	"python.lang.security.deserialization.pickle.avoid-dill",
	"python.lang.security.deserialization.pickle.avoid-pickle",
}

func TestSemgrepPlanAppliesThePackNotTheFiles(t *testing.T) {
	owasp := mustPack(t, "p/owasp-top-ten")
	plan := mustPlan(t, "p/owasp-top-ten")
	if strings.Join(plan.Pinned, ",") != "p/owasp-top-ten" || len(plan.Floor) != 559 || len(plan.Files) != 551 {
		t.Fatalf("owasp plan = pinned %v, floor %d, files %d", plan.Pinned, len(plan.Floor), len(plan.Files))
	}
	// The exclusions carry semgrep's own spelling: --exclude-rule is only
	// measured to match that, so avoid-cPickle keeps its capital P.
	if strings.Join(plan.Excluded, ",") != strings.Join(pickleRules, ",") {
		t.Fatalf("owasp-only exclusions = %v, want %v", plan.Excluded, pickleRules)
	}
	tail := strings.Join(plan.Args[len(plan.Args)-6:], " ")
	if tail != "--exclude-rule "+strings.Join(pickleRules, " --exclude-rule ") {
		t.Fatalf("exclusions are not the last arguments: %v", plan.Args[len(plan.Args)-6:])
	}
	if !strings.Contains(strings.Join(plan.Args, " "), "--config "+semgrepGHAFallbackPath) {
		t.Fatal("owasp's registry answer carried gha-curl-pipe-shell; the embedded rule must replace it")
	}
	if strings.Join(plan.Tops, ",") != strings.Join(owasp.Tops, ",") {
		t.Fatalf("owasp tops = %v, want %v", plan.Tops, owasp.Tops)
	}

	// A live pack in the same scan may want a rule the pinned one does not;
	// --exclude-rule would take it from both, so nothing is excluded.
	withLive := mustPlan(t, "p/owasp-top-ten,p/python")
	if len(withLive.Excluded) != 0 || strings.Contains(strings.Join(withLive.Args, " "), "--exclude-rule") {
		t.Fatalf("a live pack lost rules to the pinned pack's exclusions: %v", withLive.Args)
	}
	// A consumer's own config is versioned with the commit and is not a
	// registry pack, so the exclusions stand beside it.
	if local := mustPlan(t, "p/owasp-top-ten,./semgrep.yml"); len(local.Excluded) != 3 {
		t.Fatalf("a local config dropped the exclusions: %v", local.Excluded)
	}

	secrets := mustPack(t, "p/secrets")
	sp := mustPlan(t, "p/secrets")
	if len(sp.Floor) != 52 || len(sp.Excluded) != 0 || strings.Join(sp.Tops, ",") != strings.Join(secrets.Tops, ",") {
		t.Fatalf("secrets plan = %+v", sp)
	}
	if strings.Contains(strings.Join(sp.Args, " "), semgrepGHAFallbackPath) {
		t.Fatal("p/secrets never carried gha-curl-pipe-shell and must not gain cicd's replacement")
	}
}

func TestSemgrepFallbackDoesNotAddTheEmbeddedRuleTwice(t *testing.T) {
	plan := mustPlan(t, "p/security-audit,p/python")
	got := semgrepGHAFallbackArgs(plan.Args)
	if n := strings.Count(strings.Join(got, " "), semgrepGHAFallbackPath); n != 1 {
		t.Fatalf("fallback args name %s %d times: %v", semgrepGHAFallbackPath, n, got)
	}
	if !strings.Contains(strings.Join(got, " "), "--exclude-rule "+semgrepGHACurlPipeRuleID) {
		t.Fatalf("fallback args no longer exclude the upstream rule: %v", got)
	}
}

func sarifWithRules(ids ...string) []byte {
	type rule struct {
		ID string `json:"id"`
	}
	rules := make([]rule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rule{ID: id})
	}
	doc := map[string]any{"version": "2.1.0", "runs": []any{
		map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Semgrep OSS", "rules": rules}}, "results": []any{}},
	}}
	b, _ := json.Marshal(doc)
	return b
}

func TestSemgrepRuleSetHoldsThePinnedPackToItsFloor(t *testing.T) {
	p := mustPack(t, "p/security-audit")
	plan := mustPlan(t, defaultSastRulesets)
	full := append(append([]string(nil), p.IDs...), semgrepGHAFallbackLoadedID, semgrepDOMRuleLoadedID)

	rs, err := semgrepRuleSet(sarifWithRules(full...), plan)
	if err != nil {
		t.Fatalf("the full pinned set was refused: %v", err)
	}
	if rs.Count != 726 || rs.ByLanguage["cicd"] != 2 || rs.ByLanguage["python"] != 200 || rs.ByLanguage["other"] != 0 {
		t.Fatalf("rule set = %+v, want 726 with python 200 and cicd 2", rs)
	}
	if rs.Pinned != "p/security-audit = "+semgrepRulesRepo+"@"+semgrepRulesCommit || rs.Unpinned != nil {
		t.Fatalf("rule set provenance = %q / %v", rs.Pinned, rs.Unpinned)
	}

	upper := make([]string, len(full))
	for i, id := range full {
		upper[i] = strings.ToUpper(id)
	}
	if _, err := semgrepRuleSet(sarifWithRules(upper...), plan); err != nil {
		t.Fatalf("a case difference read as a missing rule: %v", err)
	}

	if _, err := semgrepRuleSet(sarifWithRules(append(full, "consumer.extra.rule")...), plan); err != nil {
		t.Fatalf("an extra rule failed the floor; extras cannot be attributed and are not checked: %v", err)
	}

	rs, err = semgrepRuleSet(sarifWithRules(full[1:]...), plan)
	if err == nil {
		t.Fatal("a pinned set missing one rule passed")
	}
	for _, want := range []string{"723 of the 724", full[0], semgrepRulesCommit[:12]} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("floor error %q does not name %q", err, want)
		}
	}
	if rs == nil || rs.Count != 725 {
		t.Fatalf("the rule set read below the floor was dropped: %+v", rs)
	}

	// The measured drift: the registry served 225 rules for the same pack.
	_, err = semgrepRuleSet(sarifWithRules(append(append([]string(nil), full[:225]...), semgrepDOMRuleLoadedID)...), plan)
	if err == nil || !strings.Contains(err.Error(), "and 494 more") {
		t.Fatalf("a 225-rule set under the pinned pack = %v, want a floor error capped at five ids", err)
	}
}

func TestSemgrepRuleSetNamesEveryPinnedPack(t *testing.T) {
	plan := mustPlan(t, "p/owasp-top-ten,p/secrets")
	// 559 + 52 less the 17 secrets rules owasp also includes: a shared rule
	// is one floor entry, not two.
	if strings.Join(plan.Pinned, ",") != "p/owasp-top-ten,p/secrets" || len(plan.Floor) != 594 {
		t.Fatalf("owasp + secrets plan = pinned %v, floor %d", plan.Pinned, len(plan.Floor))
	}
	full := append(append([]string(nil), plan.Floor...), semgrepGHAFallbackLoadedID, semgrepDOMRuleLoadedID)
	rs, err := semgrepRuleSet(sarifWithRules(full...), plan)
	if err != nil || rs.Pinned != "p/owasp-top-ten, p/secrets = "+semgrepRulesRepo+"@"+semgrepRulesCommit {
		t.Fatalf("full owasp + secrets set = %+v, %v", rs, err)
	}
	_, err = semgrepRuleSet(sarifWithRules(full[1:]...), plan)
	if err == nil || !strings.Contains(err.Error(), "593 of the 594 rules p/owasp-top-ten, p/secrets must apply") {
		t.Fatalf("floor error = %v", err)
	}
}

func TestSemgrepRuleSetWithoutThePinCountsButDoesNotVerify(t *testing.T) {
	plan := mustPlan(t, "p/python,./semgrep.yml")
	rs, err := semgrepRuleSet(sarifWithRules("python.lang.security.a.a", "semgrep.local-rule"), plan)
	if err != nil {
		t.Fatalf("an unpinned scan with rules was refused: %v", err)
	}
	if rs.Count != 2 || rs.ByLanguage["python"] != 1 || rs.ByLanguage["other"] != 1 || rs.Pinned != "" ||
		strings.Join(rs.Unpinned, ",") != "p/python" {
		t.Fatalf("rule set = %+v", rs)
	}
	if w := semgrepLiveWarning(plan.Live); !strings.Contains(w, "UNPINNED RULES — p/python") ||
		!strings.Contains(w, "Only p/security-audit, p/owasp-top-ten and p/secrets are pinned (semgrep-rules@"+semgrepRulesCommit[:12]+")") {
		t.Fatalf("live warning = %q", w)
	}
	if w := semgrepLiveWarning(nil); w != "" {
		t.Fatalf("a scan with nothing live warned: %q", w)
	}
}

// TestNonRunMatrixSemgrepRuleSet: every shape that applied no rules, or fewer
// than the pin declares, is an error, so ran=false at every threshold.
func TestNonRunMatrixSemgrepRuleSet(t *testing.T) {
	p := mustPack(t, "p/security-audit")
	pinned := mustPlan(t, defaultSastRulesets)
	live := mustPlan(t, "p/python")

	for name, c := range map[string]struct {
		report []byte
		plan   semgrepPlan
	}{
		"not json":              {[]byte("not json"), pinned},
		"no runs, pinned":       {[]byte(`{"runs":[]}`), pinned},
		"no runs, live":         {[]byte(`{"runs":[]}`), live},
		"empty rules, live":     {sarifWithRules(), live},
		"blank ids only":        {sarifWithRules(" ", ""), live},
		"pinned, only cicd's":   {sarifWithRules(semgrepGHAFallbackLoadedID), pinned},
		"pinned, one rule left": {sarifWithRules(p.IDs[0]), pinned},
	} {
		_, err := semgrepRuleSet(c.report, c.plan)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		assertNeverPasses(t, name, err == nil)
	}

	// Positive control: the matrix does not pass because the fold refuses
	// everything.
	if _, err := semgrepRuleSet(sarifWithRules(append(append([]string(nil), p.IDs...), semgrepGHAFallbackLoadedID, semgrepDOMRuleLoadedID)...), pinned); err != nil {
		t.Fatalf("control: the full pinned set errored: %v", err)
	}
}

// TestSemgrepScriptStagesBeforeItScans pins the order that makes a staging
// failure a refusal: the error file is truncated first, staging runs before
// semgrep, and the guard that skips the scan sits between them.
func TestSemgrepScriptStagesBeforeItScans(t *testing.T) {
	at := func(s string) int {
		i := strings.Index(semgrepScript, s)
		if i < 0 {
			t.Fatalf("semgrepScript no longer contains %q", s)
		}
		return i
	}
	truncate := at(": > " + semgrepPackErrPath)
	refuseExisting := at(`already exists in the scan image`)
	stage := at(`cp "` + semgrepPackSrc + `/$f" "$d/"`)
	guard := at("if [ -s " + semgrepPackErrPath + " ]; then\n  echo 2 > /tmp/semgrep.exit")
	scan := at("opengrep scan ")
	if truncate > refuseExisting || refuseExisting > stage || stage > guard || guard > scan {
		t.Fatalf("staging steps out of order:\n%s", semgrepScript)
	}
	if strings.Contains(semgrepScript, "set -e") {
		t.Fatal("set -e would kill the script before it records why staging failed")
	}
}
