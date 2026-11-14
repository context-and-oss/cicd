// The pinned SAST rule sets: which semgrep-rules commit cicd scans with when a
// consumer asks for p/security-audit (the default), p/owasp-top-ten or
// p/secrets, which rules that commit must load for each, and how to tell a
// scan that loaded them from one that did not.
//
// Deliberately untagged (no //go:build !unit_test): this is manifest parsing,
// argument building and SARIF reading, so semgreppack_test.go drives all of it
// under `-tags unit_test`. sast.go only fetches the commit and mounts it.
//
// Why a pin at all. `--config p/security-audit` is resolved by the Semgrep
// registry at scan time, and the registry changes the pack without a version.
// Measured on the same consumer commit: 725 rules on 2026-10-21, 225 three
// days later, and the evidence said "opengrep: 0 findings" both times. A
// finding count is a measurement over the files examined AND the rules
// applied; Examined carried the first denominator, and nothing carried the
// second. The pack is now read from a fixed commit, the rules it must load are
// written down here, and a scan that loaded fewer is a non-run.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	semgrepRulesRepo   = "https://github.com/semgrep/semgrep-rules"
	semgrepRulesCommit = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"

	// Where sast.go mounts the fetched tree and the staging lists. The script
	// copies the manifest's files out of semgrepPackSrc into /<top>/…, so the
	// rules load under exactly the ids the registry gives them; see
	// semgrepPackStaging.
	semgrepPackSrc     = "/cicd-semgrep-pack/src"
	semgrepPackFiles   = "/cicd-semgrep-pack/files"
	semgrepPackTops    = "/cicd-semgrep-pack/tops"
	semgrepPackErrPath = "/tmp/semgrep.pack.err"
)

var (
	//go:embed rules/semgrep-security-audit.txt
	semgrepSecurityAuditManifest string
	//go:embed rules/semgrep-owasp-top-ten.txt
	semgrepOwaspTopTenManifest string
	//go:embed rules/semgrep-secrets.txt
	semgrepSecretsManifest string
)

// semgrepPinnedPackDef is one registry id cicd intercepts and the manifest it
// is read from instead. All of them are pinned to the same semgrep-rules
// commit, so two pinned packs in one scan can never disagree about a rule
// they share.
type semgrepPinnedPackDef struct {
	Name     string
	Manifest string
	// GHAFallback is true when the registry pack carries the upstream
	// gha-curl-pipe-shell rule, which every manifest leaves out; cicd's
	// runtime-adapted equivalent is loaded in its place. A pack that never carried
	// it does not get it.
	GHAFallback bool
}

// semgrepPinnedPackDefs are the packs cicd pins, in the order the evidence
// names them. p/security-audit is the module's default, so every consumer that
// names no ruleset gets a pinned set. A consumer who names one of these
// explicitly gets the same thing — there is no second spelling that still
// reaches the live registry.
//
// A function rather than a package variable so the embedded manifests are
// read when it is called, not ordered against package initialisation.
func semgrepPinnedPackDefs() []semgrepPinnedPackDef {
	return []semgrepPinnedPackDef{
		{Name: "p/security-audit", Manifest: semgrepSecurityAuditManifest, GHAFallback: true},
		{Name: "p/owasp-top-ten", Manifest: semgrepOwaspTopTenManifest, GHAFallback: true},
		{Name: "p/secrets", Manifest: semgrepSecretsManifest},
	}
}

// semgrepPack is one parsed manifest.
type semgrepPack struct {
	// Name and GHAFallback come from the pack's definition; parseSemgrepPack
	// leaves them empty.
	Name        string
	GHAFallback bool
	// Files are the rule files to stage, unique and sorted.
	Files []string
	// IDs are the rule ids the scan must report as loaded, lowercased:
	// semgrep's SARIF and the registry disagree on case for a handful of ids,
	// and a case difference is not a missing rule.
	IDs []string
	// Tops are the top-level directories of Files, sorted. Each becomes a
	// root-level --config directory, which is what makes semgrep derive the
	// registry's id rather than one prefixed with a staging path.
	Tops []string
	// ByFile lists each file's lowercased ids, which is what tells a plan the
	// other rules a staged file brings with it.
	ByFile map[string][]string
	// Spelled maps a lowercased id to the spelling semgrep derives for it — the
	// path part lowercased, the rule's own id as written — which is the only
	// spelling --exclude-rule is guaranteed to match.
	Spelled map[string]string
}

// semgrepReservedRoots are root-level names a top directory must never take:
// the staging step creates /<top>, and a rule directory called "bin" or "src"
// would collide with the image or with the scanned tree's own mount.
var semgrepReservedRoots = map[string]bool{
	"bin": true, "boot": true, "dev": true, "etc": true, "home": true, "lib": true,
	"lib64": true, "media": true, "mnt": true, "opt": true, "proc": true,
	"root": true, "run": true, "sbin": true, "src": true, "srv": true, "sys": true,
	"tmp": true, "usr": true, "var": true, "cicd-rules": true, "cicd-semgrep-pack": true,
}

// loadSemgrepPacks parses every pinned manifest. It runs at every scan, and a
// manifest that does not parse fails the scan whichever pack was asked for:
// the plan reads all of them to know which rules a staged file carries.
func loadSemgrepPacks() ([]semgrepPack, error) {
	var packs []semgrepPack
	for _, d := range semgrepPinnedPackDefs() {
		p, err := parseSemgrepPack(d.Manifest)
		if err != nil {
			return nil, errors.New("opengrep: " + d.Name + " " + strings.TrimPrefix(err.Error(), "opengrep: "))
		}
		p.Name, p.GHAFallback = d.Name, d.GHAFallback
		packs = append(packs, p)
	}
	return packs, nil
}

// parseSemgrepPack reads the manifest and refuses anything the staging step
// could not reproduce exactly. It is checked at every scan, not only by its
// test: a manifest that does not parse means cicd cannot say which rules the
// scan was meant to load, and that is a non-run like any other.
func parseSemgrepPack(raw string) (semgrepPack, error) {
	p := semgrepPack{ByFile: map[string][]string{}, Spelled: map[string]string{}}
	tops := map[string]bool{}
	for n, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := "opengrep: pinned rule manifest line " + strconv.Itoa(n+1)
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return semgrepPack{}, errors.New(at + ": want \"<path> <rule id>\", got " + strconv.Quote(line))
		}
		path, id := fields[0], strings.ToLower(fields[1])
		if err := semgrepPackPathOK(path); err != nil {
			return semgrepPack{}, errors.New(at + ": " + err.Error())
		}
		// The id is derived from the path by semgrep, so a row whose id does
		// not start with its own path is a row that cannot be what it claims.
		prefix := strings.ToLower(semgrepPackIDPrefix(path))
		if !strings.HasPrefix(id, prefix) || len(id) == len(prefix) {
			return semgrepPack{}, errors.New(at + ": rule id " + strconv.Quote(id) + " does not belong to " + path)
		}
		if _, dup := p.Spelled[id]; dup {
			return semgrepPack{}, errors.New(at + ": rule id " + strconv.Quote(id) + " listed twice")
		}
		p.Spelled[id] = prefix + fields[1][len(prefix):]
		top, _, _ := strings.Cut(path, "/")
		if semgrepReservedRoots[top] {
			return semgrepPack{}, errors.New(at + ": top-level directory " + strconv.Quote(top) + " collides with a root path the scan container uses")
		}
		tops[top] = true
		if _, seen := p.ByFile[path]; !seen {
			p.Files = append(p.Files, path)
		}
		p.ByFile[path] = append(p.ByFile[path], id)
		p.IDs = append(p.IDs, id)
	}
	if len(p.IDs) == 0 {
		return semgrepPack{}, errors.New("opengrep: pinned rule manifest lists no rules")
	}
	for t := range tops {
		p.Tops = append(p.Tops, t)
	}
	sort.Strings(p.Files)
	sort.Strings(p.IDs)
	sort.Strings(p.Tops)
	return p, nil
}

// semgrepPackPathOK holds a manifest path to what the staging script can copy
// without quoting: a relative YAML file under at least one directory, in a
// charset with no shell meaning, and never a rule's own test fixture.
func semgrepPackPathOK(path string) error {
	for _, c := range path {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '.', c == '-', c == '_':
		default:
			return errors.New("path " + strconv.Quote(path) + " has a character outside [A-Za-z0-9/._-]")
		}
	}
	switch {
	case strings.HasPrefix(path, "/"), strings.Contains(path, ".."), strings.Contains(path, "//"):
		return errors.New("path " + strconv.Quote(path) + " is not a plain relative path")
	case !strings.Contains(path, "/"):
		return errors.New("path " + strconv.Quote(path) + " is not under a language directory")
	case !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml"):
		return errors.New("path " + strconv.Quote(path) + " is not a YAML rule file")
	case strings.Contains(path, ".test."):
		return errors.New("path " + strconv.Quote(path) + " is a rule test fixture, not a rule")
	}
	return nil
}

// semgrepPackIDPrefix is the id prefix semgrep derives for a rule file staged
// as /<dir>/<stem>/<file> and loaded with --config /<top>: the directories and
// the file's stem, dot-joined, then the rule's own id.
func semgrepPackIDPrefix(path string) string {
	dir, file := path[:strings.LastIndex(path, "/")], path[strings.LastIndex(path, "/")+1:]
	stem := strings.TrimSuffix(strings.TrimSuffix(file, ".yaml"), ".yml")
	return strings.ReplaceAll(dir, "/", ".") + "." + stem + "."
}

// semgrepPackStaging is the list the scan script copies from: one
// "<path> <destination dir>" line per file. Each file gets a directory named
// after its stem, because that extra path component is what turns semgrep's
// derived id into the registry's <dir>.<stem>.<rule>.
func semgrepPackStaging(files []string) string {
	var b strings.Builder
	for _, f := range files {
		dir := f[:strings.LastIndex(f, "/")]
		stem := strings.TrimSuffix(strings.TrimSuffix(f[len(dir)+1:], ".yaml"), ".yml")
		b.WriteString(f + " /" + dir + "/" + stem + "\n")
	}
	return b.String()
}

// semgrepPlan is what a --sast-rulesets value turns into.
type semgrepPlan struct {
	// Inline adds the first-party DOM rule and analyses inline JavaScript for
	// the audit/OWASP defaults. Secrets-only and custom-only scans stay explicit.
	Inline bool
	// Args are the arguments passed to semgrep: --config pairs, then any
	// --exclude-rule pairs.
	Args []string
	// Pinned names the pinned packs in the scan, in semgrepPinnedPackDefs
	// order. Any entry arms the floor in semgrepRuleSet.
	Pinned []string
	// Files and Tops are what the scan script stages: the union of the pinned
	// packs' files, and their top-level directories.
	Files []string
	Tops  []string
	// Floor is every lowercased id the pinned packs in the scan must load.
	Floor []string
	// Excluded are rules a staged file carries that no requested pack
	// includes, passed as --exclude-rule so the scan applies the packs that
	// were asked for and not the files they happen to live in.
	Excluded []string
	// Live are the registry packs the scan fetches at run time, which nothing
	// pins and nothing can verify.
	Live []string
	// Langs are the language directories every pinned manifest knows, which
	// is how semgrepRuleLanguage files a rule whatever pack it came from.
	Langs map[string]bool
}

// semgrepPlanFor validates a ruleset list and replaces each pinned pack with
// the staged directories, plus the runtime-adapted gha-curl-pipe-shell rule when
// a requested pack carries the upstream one the manifests leave out. However
// many pinned packs are named, their files are staged once, at the position
// of the first.
//
// A config the consumer keeps in its own tree is neither pinned nor live: it
// is versioned with the commit under scan, so it is not listed in Live.
//
// Exclusions are skipped whenever a live registry config is in the scan.
// --exclude-rule removes a rule id from every config, so excluding
// python.lang.security.deserialization.pickle.avoid-pickle for a pinned
// p/owasp-top-ten would also remove it from a live p/python that asked for
// it, and that pack's rule set would shrink with nothing to say so. The scan
// then loads the co-located rules too: more than the pinned packs name,
// which the recorded count shows, rather than less than the live one did.
func semgrepPlanFor(rulesets string, packs []semgrepPack) (semgrepPlan, error) {
	configs, err := semgrepConfigFlags(rulesets)
	if err != nil {
		return semgrepPlan{}, err
	}
	byName := map[string]semgrepPack{}
	for _, p := range packs {
		byName[p.Name] = p
	}
	requested := map[string]bool{}
	live := false
	for i := 1; i < len(configs); i += 2 {
		if _, ok := byName[configs[i]]; ok {
			requested[configs[i]] = true
		} else if semgrepIsRegistryConfig(configs[i]) {
			live = true
		}
	}

	plan := semgrepPlan{
		Langs:  map[string]bool{},
		Inline: requested["p/security-audit"] || requested["p/owasp-top-ten"],
	}
	files := map[string]bool{}
	tops := map[string]bool{}
	floor := map[string]bool{}
	fallback := false
	for _, p := range packs {
		for _, t := range p.Tops {
			plan.Langs[t] = true
		}
		if !requested[p.Name] {
			continue
		}
		plan.Pinned = append(plan.Pinned, p.Name)
		fallback = fallback || p.GHAFallback
		for _, f := range p.Files {
			files[f] = true
			t, _, _ := strings.Cut(f, "/")
			tops[t] = true
		}
		for _, id := range p.IDs {
			floor[id] = true
		}
	}
	plan.Files = sortedKeys(files)
	plan.Tops = sortedKeys(tops)
	plan.Floor = sortedKeys(floor)

	staged := false
	for i := 1; i < len(configs); i += 2 {
		c := configs[i]
		switch {
		case requested[c]:
			if staged {
				continue
			}
			staged = true
			for _, t := range plan.Tops {
				plan.Args = append(plan.Args, "--config", "/"+t)
			}
			if fallback {
				plan.Args = append(plan.Args, "--config", semgrepGHAFallbackPath)
			}
			if plan.Inline {
				plan.Args = append(plan.Args, "--config", semgrepDOMRulePath)
			}
		case semgrepIsRegistryConfig(c):
			plan.Live = append(plan.Live, c)
			plan.Args = append(plan.Args, "--config", c)
		default:
			plan.Args = append(plan.Args, "--config", c)
		}
	}

	if live {
		return plan, nil
	}
	excluded := map[string]bool{}
	for _, p := range packs {
		for _, f := range plan.Files {
			for _, id := range p.ByFile[f] {
				if !floor[id] {
					excluded[p.Spelled[id]] = true
				}
			}
		}
	}
	plan.Excluded = sortedKeys(excluded)
	for _, id := range plan.Excluded {
		plan.Args = append(plan.Args, "--exclude-rule", id)
	}
	return plan, nil
}

// semgrepIsRegistryConfig reports whether semgrep fetches a config from its
// registry: the p/ (pack), r/ (rule) and s/ (snippet) namespaces.
func semgrepIsRegistryConfig(c string) bool {
	return strings.HasPrefix(c, "p/") || strings.HasPrefix(c, "r/") || strings.HasPrefix(c, "s/")
}

// semgrepLiveWarning discloses the registry configs nobody pinned. Their rule
// count is still recorded, but a count with no floor beside it cannot say
// whether it is the set the pack held yesterday.
func semgrepLiveWarning(live []string) string {
	if len(live) == 0 {
		return ""
	}
	var names []string
	for _, d := range semgrepPinnedPackDefs() {
		names = append(names, d.Name)
	}
	pinned := names[0] + " is"
	if len(names) > 1 {
		pinned = strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1] + " are"
	}
	return "opengrep: UNPINNED RULES — " + strings.Join(live, ", ") +
		" fetched live from the Semgrep registry at scan time; the rule count is recorded under sources[].rules but cannot be verified, " +
		"so the same commit can be scanned with different rules on different days. Only " + pinned +
		" pinned (semgrep-rules@" + semgrepRulesCommit[:12] + ")"
}

// semgrepRuleSet reads which rules the scan actually loaded and, when a
// pinned pack was asked for, holds the scan to the plan's floor.
//
// Semgrep's SARIF lists every loaded rule under runs[].tool.driver.rules,
// whether or not it matched, which is the only first-hand account of the rule
// set a scan used. Reading it after the run, rather than trusting the staging
// step, also catches a rule semgrep dropped at load time.
//
// Apart from the separately required DOM and workflow-compatibility configs,
// rules the scan loaded beyond the floor are not checked: a live pack or a
// local config may add any number, and none of them can be attributed to the
// pin. The floor is the claim cicd can stand behind; a ceiling is not. With
// only pinned packs in the scan the ceiling holds by construction instead:
// every file a pinned manifest names is in semgrep-security-audit.txt, whose
// staged files load exactly its ids (measured: 724 plus cicd's one), so every
// co-located rule is known to the plan and excluded.
//
// The RuleSet is returned with the error, so the findings of a scan that ran
// below its floor still reach the report — they are real findings, just not
// the whole measurement.
func semgrepRuleSet(report []byte, plan semgrepPlan) (*RuleSet, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil, errors.New("opengrep: could not read the loaded rules from the report: " + err.Error())
	}
	loaded := map[string]bool{}
	rs := &RuleSet{ByLanguage: map[string]int{}, Unpinned: plan.Live}
	for _, run := range doc.Runs {
		for _, r := range run.Tool.Driver.Rules {
			id := strings.ToLower(strings.TrimSpace(r.ID))
			if id == "" || loaded[id] {
				continue
			}
			loaded[id] = true
			rs.ByLanguage[semgrepRuleLanguage(id, plan.Langs)]++
		}
	}
	rs.Count = len(loaded)
	if len(rs.ByLanguage) == 0 {
		rs.ByLanguage = nil
	}
	packs := strings.Join(plan.Pinned, ", ")
	if len(plan.Pinned) > 0 {
		rs.Pinned = packs + " = " + semgrepRulesRepo + "@" + semgrepRulesCommit
	}

	if rs.Count == 0 {
		return rs, errors.New("opengrep: the scan loaded no rules, so it applied nothing; zero findings from it is not a result")
	}
	if plan.Inline && !loaded[semgrepDOMRuleLoadedID] {
		return rs, errors.New("opengrep: cicd's required DOM-text-to-HTML rule did not load; the default scan is incomplete")
	}
	var missing []string
	for _, id := range plan.Floor {
		if !loaded[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		shown := missing
		if len(shown) > 5 {
			shown = shown[:5]
		}
		msg := fmt.Sprintf("opengrep: the pinned rule set loaded %d of the %d rules %s must apply (semgrep-rules@%s); missing: %s",
			len(plan.Floor)-len(missing), len(plan.Floor), packs, semgrepRulesCommit[:12], strings.Join(shown, ", "))
		if more := len(missing) - len(shown); more > 0 {
			msg += fmt.Sprintf(" and %d more", more)
		}
		return rs, errors.New(msg + ". A rule set below its floor is not the scan that was asked for")
	}
	if semgrepUsesGHAFallback(plan.Args) && !loaded[semgrepGHAFallbackLoadedID] {
		return rs, errors.New("opengrep: required workflow compatibility rule did not load; the scan is incomplete")
	}
	return rs, nil
}

// semgrepRuleLanguage files a rule under the language directory its id starts
// with. Configs under cicd's rule directory start with that directory (see
// semgrepCicdRuleDir) and are filed as "cicd"; anything else — a consumer's
// local config, a live rule outside the pinned tree's layout — is "other"
// rather than a guess.
func semgrepRuleLanguage(id string, tops map[string]bool) string {
	first, _, _ := strings.Cut(id, ".")
	switch {
	case tops[first]:
		return first
	case first == semgrepCicdRuleDir:
		return "cicd"
	default:
		return "other"
	}
}
