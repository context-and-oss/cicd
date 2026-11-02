// Which package manager installs a Node project, and the shell that runs it.
//
// Deliberately untagged (no //go:build !unit_test): detection is a decision
// over package.json, the directory listing and the head of yarn.lock, and the
// script fragments are strings, so nodeinstall_test.go drives all of it with
// `go test -tags unit_test ./...`.
//
// Both auto-detected Node legs used to run `npm install` whatever the project
// used. In a pnpm or yarn repository npm ignores pnpm-lock.yaml and yarn.lock,
// resolves every range afresh, and the leg then lints or tests a dependency
// tree nobody locked — or, on a pnpm workspace (changesets, measured), fails
// to install at all, and the leg named npm as the cause. The project says
// which manager it uses; this file reads that and refuses when it cannot.
package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// nodePM is the package manager a Node project is installed with.
type nodePM struct {
	name     string // "npm", "pnpm" or "yarn"
	berry    bool   // yarn 2+; meaningless for the other two
	version  string // from packageManager; "" when the project declares none
	pinned   bool   // packageManager carries a +<algo>.<hash> corepack verifies
	lockfile string // the lockfile the install is frozen to; "" when none
}

// npmDefault is the manager for a directory with no package.json and no
// lockfile: what both legs ran before detection existed.
var npmDefault = nodePM{name: "npm"}

// nodeLockfiles maps each lockfile name to the manager that writes it.
var nodeLockfiles = map[string]string{
	"package-lock.json":   "npm",
	"npm-shrinkwrap.json": "npm",
	"pnpm-lock.yaml":      "pnpm",
	"yarn.lock":           "yarn",
	"bun.lock":            "bun",
	"bun.lockb":           "bun",
}

// packageManagerField is corepack's grammar for package.json#packageManager:
// name@version, optionally +<algorithm>.<hex digest>.
var packageManagerField = regexp.MustCompile(`^(@?[a-z0-9][a-z0-9._-]*)@([0-9][0-9A-Za-z.+-]*?)(\+[a-z0-9]+\.[0-9a-fA-F]+)?$`)

// detectNodePackageManager decides which manager installs the project whose
// package.json is pkgJSON ("" when there is none), whose directory holds
// entries, and whose yarn.lock begins with yarnLock ("" when absent).
//
// packageManager is read first because corepack enforces it: a project that
// declares pnpm cannot be installed by anything else without corepack
// refusing. The lockfile confirms it. Every disagreement is an error, never a
// guess — installing a pnpm project with yarn because yarn.lock was also
// committed would lint a tree the team never resolved, which is the defect
// this file exists to close. Warnings name what cicd could not hold fixed.
func detectNodePackageManager(pkgJSON string, entries []string, yarnLock string) (nodePM, []string, error) {
	declared, err := declaredPackageManager(pkgJSON)
	if err != nil {
		return nodePM{}, nil, err
	}

	byManager := map[string][]string{}
	for _, e := range entries {
		if pm, ok := nodeLockfiles[strings.TrimSuffix(e, "/")]; ok && !strings.HasSuffix(e, "/") {
			byManager[pm] = append(byManager[pm], e)
		}
	}
	kinds := make([]string, 0, len(byManager))
	for k := range byManager {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	var warnings []string
	pm := nodePM{}
	switch {
	case declared.name != "":
		pm = declared
		if files := byManager[pm.name]; len(files) > 0 {
			sort.Strings(files)
			pm.lockfile = files[0]
			for _, k := range kinds {
				if k != pm.name {
					warnings = append(warnings, fmt.Sprintf("%s is ignored: packageManager declares %s",
						strings.Join(sortedCopy(byManager[k]), ", "), pm.name))
				}
			}
		} else if len(kinds) > 0 {
			return nodePM{}, nil, fmt.Errorf("package.json declares packageManager %s@%s but the only lockfile is %s; "+
				"commit the %s lockfile or correct packageManager", pm.name, pm.version,
				strings.Join(lockfilesOf(byManager, kinds), ", "), pm.name)
		}
	case len(kinds) > 1:
		return nodePM{}, nil, fmt.Errorf("lockfiles from more than one package manager (%s) and no packageManager "+
			"in package.json to choose between them; delete the stale ones or declare packageManager",
			strings.Join(lockfilesOf(byManager, kinds), ", "))
	case len(kinds) == 1:
		pm.name = kinds[0]
		pm.lockfile = sortedCopy(byManager[pm.name])[0]
	default:
		pm = npmDefault
	}

	if pm.name == "bun" {
		return nodePM{}, nil, fmt.Errorf("the project is installed with bun (%s), which the auto-detected Node legs "+
			"do not support; run the suite through the witnessed test leg (--test-cmd) with its own install",
			pmSource(pm))
	}
	if pm.name == "yarn" {
		if err := resolveYarnGeneration(&pm, yarnLock); err != nil {
			return nodePM{}, nil, err
		}
	}

	switch {
	case pm.name == "npm" && pm.version != "":
		// corepack shims pnpm and yarn, not npm: the image's bundled npm runs.
		warnings = append(warnings, "packageManager declares npm@"+pm.version+", which cicd does not install: "+
			"the node image's bundled npm ran the install")
	case pm.name != "npm" && pm.version == "":
		warnings = append(warnings, pm.name+" version chosen by corepack: package.json declares no packageManager; "+
			"declare one (with its +sha512 hash) to fix the version that installs")
	case pm.name != "npm" && !pm.pinned:
		warnings = append(warnings, pm.name+"@"+pm.version+" from packageManager is unpinned: it carries no "+
			"+sha512 hash, so corepack does not verify the download")
	}
	if pm.lockfile == "" && pkgJSON != "" {
		warnings = append(warnings, "no lockfile: "+pm.installLabel()+" resolved every dependency range afresh, "+
			"so this run checked versions nobody locked")
	}
	return pm, warnings, nil
}

// declaredPackageManager reads package.json#packageManager. A package.json
// that is not JSON is an error: every manager would refuse it at install, and
// "could not read the project" is the true reason, not "no packageManager".
func declaredPackageManager(pkgJSON string) (nodePM, error) {
	if strings.TrimSpace(pkgJSON) == "" {
		return nodePM{}, nil
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(pkgJSON), &pkg); err != nil {
		return nodePM{}, fmt.Errorf("package.json is not a JSON object: %v", err)
	}
	raw, ok := pkg["packageManager"]
	if !ok {
		return nodePM{}, nil
	}
	var field string
	if err := json.Unmarshal(raw, &field); err != nil {
		return nodePM{}, fmt.Errorf("package.json packageManager is not a string: %s", string(raw))
	}
	m := packageManagerField.FindStringSubmatch(strings.TrimSpace(field))
	if m == nil {
		return nodePM{}, fmt.Errorf("package.json packageManager %q is not name@version[+hash]", field)
	}
	switch m[1] {
	case "npm", "pnpm", "yarn", "bun":
	default:
		return nodePM{}, fmt.Errorf("package.json packageManager names %q; the auto-detected Node legs install "+
			"with npm, pnpm or yarn", m[1])
	}
	return nodePM{name: m[1], version: m[2], pinned: m[3] != ""}, nil
}

// resolveYarnGeneration tells yarn classic from yarn berry. The two share a
// binary name and a lockfile name and nothing else: classic's yarn.lock opens
// with `# yarn lockfile v1`, berry's carries a `__metadata:` block, and the
// install flags, the script switch and the way binaries resolve all differ.
// A berry lockfile with no packageManager is an error: corepack's default yarn
// is classic, which cannot read it.
func resolveYarnGeneration(pm *nodePM, yarnLock string) error {
	byVersion, versionKnown := false, pm.version != ""
	if versionKnown {
		major, err := strconv.Atoi(strings.SplitN(pm.version, ".", 2)[0])
		if err != nil {
			return fmt.Errorf("package.json packageManager yarn@%s has no readable major version", pm.version)
		}
		byVersion = major >= 2
	}
	if pm.lockfile == "" {
		pm.berry = byVersion
		return nil
	}
	var byLock bool
	switch {
	case strings.Contains(yarnLock, "\n__metadata:") || strings.HasPrefix(yarnLock, "__metadata:"):
		byLock = true
	case strings.Contains(yarnLock, "# yarn lockfile v1"):
		byLock = false
	default:
		return fmt.Errorf("yarn.lock is neither a yarn 1 lockfile (# yarn lockfile v1) nor a yarn 2+ one " +
			"(__metadata:), so which yarn installs it is unknown")
	}
	switch {
	case !versionKnown && byLock:
		return fmt.Errorf("yarn.lock is a yarn 2+ lockfile and package.json declares no packageManager; " +
			"corepack would install it with yarn 1, which cannot read it. Declare packageManager (yarn@<version>)")
	case versionKnown && byVersion != byLock:
		gen := map[bool]string{true: "yarn 2+", false: "yarn 1"}
		return fmt.Errorf("package.json declares yarn@%s but yarn.lock is a %s lockfile", pm.version, gen[byLock])
	}
	pm.berry = byLock
	return nil
}

// installLabel names the install in messages: what a consumer would type to
// reproduce it.
func (pm nodePM) installLabel() string {
	switch {
	case pm.name == "npm" && pm.lockfile != "":
		return "npm ci"
	case pm.name == "npm":
		return "npm install"
	default:
		return pm.name + " install"
	}
}

// installCommand is the install the leg runs. Lifecycle scripts never run: an
// install script is the project's arbitrary code, and a lint or test leg has
// no reason to execute it. With a lockfile every manager installs frozen, so a
// lockfile out of date with package.json fails the install (recorded, and
// named by the leg) rather than resolving a tree nobody reviewed.
func (pm nodePM) installCommand() string {
	frozen := pm.lockfile != ""
	switch {
	case pm.name == "pnpm" && frozen:
		return "pnpm install --frozen-lockfile --ignore-scripts"
	case pm.name == "pnpm":
		return "pnpm install --ignore-scripts"
	case pm.name == "yarn" && pm.berry && frozen:
		// Berry has no --ignore-scripts; enableScripts is its setting.
		return "YARN_ENABLE_SCRIPTS=false yarn install --immutable"
	case pm.name == "yarn" && pm.berry:
		return "YARN_ENABLE_SCRIPTS=false yarn install"
	case pm.name == "yarn" && frozen:
		return "yarn install --frozen-lockfile --ignore-scripts"
	case pm.name == "yarn":
		return "yarn install --ignore-scripts"
	case frozen:
		return "npm ci --ignore-scripts"
	default:
		return "npm install --ignore-scripts"
	}
}

// installLine is the shell line that installs and records the exit. pnpm and
// yarn come from corepack, which fetches the declared version (and verifies
// its hash when packageManager pins one); the download prompt is switched off
// because there is no one to answer it. corepack enable is inside the
// recorded exit: a manager that could not be fetched is an install that failed.
func (pm nodePM) installLine() string {
	cmd := pm.installCommand()
	if pm.name != "npm" {
		cmd = "export COREPACK_ENABLE_DOWNLOAD_PROMPT=0; corepack enable && " + cmd
	}
	return "{ " + cmd + "; } >/dev/null 2>&1; echo $? > " + nodeInstallExitPath
}

// exec is how a project binary is run without ever being fetched. `npx --no`
// resolves the way node does — up through a workspace root — and refuses to
// download, for npm, pnpm and yarn 1, which all leave node_modules/.bin.
// Yarn berry's default Plug'n'Play install leaves no node_modules at all, so
// only `yarn <bin>` resolves there (measured, yarn 4.9.1); it does not fetch
// either, and a missing binary exits 1 with a usage error on stdout.
func (pm nodePM) exec() string {
	if pm.berry {
		return "yarn"
	}
	return "npx --no --"
}

// node is how a script asks the project's own module resolution a question:
// under Plug'n'Play `require` only resolves inside `yarn node`.
func (pm nodePM) node() string {
	if pm.berry {
		return "yarn node"
	}
	return "node"
}

// pmSource says where the decision came from, for messages.
func pmSource(pm nodePM) string {
	if pm.version != "" {
		return "packageManager " + pm.name + "@" + pm.version
	}
	if pm.lockfile != "" {
		return pm.lockfile
	}
	return "no packageManager and no lockfile"
}

// installRecord is what a Node leg knows about the install it ran: which
// command, and the exit it recorded. Both are "" when the leg ran no install
// (a prepared container), and an exit that is "" or unreadable is unknown,
// never a success.
type installRecord struct {
	label    string
	exit     string
	corepack bool // the manager itself was fetched by corepack first
}

// record pairs the install pm runs with the exit the script left behind.
func (pm nodePM) record(exit string) installRecord {
	return installRecord{label: pm.installLabel(), exit: exit, corepack: pm.name != "npm"}
}

// installFailureCauses names what makes an install fail, for remedies. A
// corepack-managed install has one cause npm does not: the manager is fetched
// from registry.npmjs.org before anything else, and a network that blocks it
// fails the install before a single dependency was asked for.
func installFailureCauses(r installRecord) string {
	causes := "a lockfile out of date with package.json, a registry or feed it could not reach"
	if r.corepack {
		causes += ", or corepack unable to fetch " + strings.SplitN(r.label, " ", 2)[0] + " itself from registry.npmjs.org"
	}
	return causes
}

// failed reports a readable non-zero exit, and the exit as written.
func (r installRecord) failed() (string, bool) {
	ie := strings.TrimSpace(r.exit)
	n, err := strconv.Atoi(ie)
	return ie, err == nil && n != 0
}

// known reports whether the exit could be read at all.
func (r installRecord) known() bool {
	_, err := strconv.Atoi(strings.TrimSpace(r.exit))
	return err == nil
}

// name is the install as messages say it; a record with no label still names
// something a reader can act on.
func (r installRecord) name() string {
	if r.label == "" {
		return "the dependency install"
	}
	return r.label
}

// nodeFeedEnv is the configuration that points a Node install at the private
// feed: plain variables, and the names the token is bound to as a secret.
//
// npm reads NPM_CONFIG_*. pnpm 11 does not — measured against pnpm 11.19.0
// with a local registry logging requests, NPM_CONFIG_REGISTRY was ignored and
// PNPM_CONFIG_REGISTRY plus PNPM_CONFIG_//<dart>/:_authToken sent
// `Authorization: Bearer`. Both are set, both nerf-darted, so the token goes
// to the feed's host and nowhere else.
//
// Yarn gets nothing. Berry's YARN_NPM_AUTH_TOKEN is not scoped to a host: a
// scope the project routes to another registry in .yarnrc.yml would be sent
// the same token. nodeFeedWarning says the feed was not applied instead.
//
// With npmrc routing the registry variables are left out and only the token
// is bound. The feed then serves only what the project's own .npmrc routes to
// it (`@scope:registry=<feed>`), and everything else resolves from the public
// registry. That is the mode for a feed that has no upstream to the public
// registry, because pointing the whole install at such a feed fails every
// public package with a 404. The routing has to come from the project's .npmrc
// instead of from cicd: pnpm 11.19.0 ignored a scoped registry set through
// PNPM_CONFIG_@scope:registry, NPM_CONFIG_@scope:registry or its lowercase
// spellings (measured, same local registry), while it honoured the same line
// in an .npmrc together with the token variable below.
func nodeFeedEnv(feedURL, routing string) (env [][2]string, secretKeys []string) {
	npmKey := npmAuthEnvKey(feedURL)
	secretKeys = []string{npmKey, "PNPM_CONFIG_" + strings.TrimPrefix(npmKey, "NPM_CONFIG_")}
	if routing == npmRoutingNpmrc {
		return nil, secretKeys
	}
	reg := npmRegistryURL(feedURL)
	return [][2]string{{"NPM_CONFIG_REGISTRY", reg}, {"PNPM_CONFIG_REGISTRY", reg}}, secretKeys
}

// nodeFeedWarning names a feed credential the install did not use.
func nodeFeedWarning(pm nodePM, hasFeed bool) string {
	if !hasFeed || pm.name != "yarn" {
		return ""
	}
	return "the private npm feed credential was not applied to this yarn install: cicd sets it as npm and pnpm " +
		"configuration only, because yarn's own token setting is not scoped to the feed's host. An install that " +
		"needs the feed fails and says so; run it through the witnessed test leg (--test-cmd) with your .yarnrc.yml"
}

// nodeFeedRoutingWarning names an npmrc routing the project's .npmrc does not
// carry out. With npmrc routing cicd binds the token and nothing else, so an
// .npmrc that sends no registry to the feed's host leaves every package on the
// public registry: the private ones fail with a 404 that names the package and
// never mentions the routing. Saying so up front is the difference between a
// one-line fix and a hunt through install output.
//
// npmrc is the project's own .npmrc as read beside its package.json, "" when it
// has none. That is where npm and pnpm both read project configuration for an
// install run there, which is the directory the legs install in.
func nodeFeedRoutingWarning(pm nodePM, routing, feedURL, npmrc string) string {
	if routing != npmRoutingNpmrc || feedURL == "" || pm.name == "yarn" || npmrcRoutesTo(npmrc, feedURL) {
		return ""
	}
	return "npm-feed-routing is npmrc, but the project's .npmrc routes no registry to the private feed's host, so " +
		"cicd's token is never used and private packages resolve from the public registry. Add " +
		"`@<scope>:registry=` followed by the feed URL to the .npmrc beside package.json"
}

// npmrcRoutesTo reports whether an .npmrc sends any registry, scoped or not,
// where the feed token applies. That is decided the way npm matches a token
// to a request: by nerf dart, and for the dart's path and every path below it,
// so a scheme or a trailing slash on either side does not matter. A value that
// expands a variable cannot be resolved here and counts as routed: a warning
// on a correct file would teach people to ignore it.
func npmrcRoutesTo(npmrc, feedURL string) bool {
	dart := func(u string) string {
		return strings.TrimSuffix(strings.TrimPrefix(npmAuthEnvKey(u), "NPM_CONFIG_"), ":_authToken")
	}
	want := dart(feedURL)
	for _, line := range strings.Split(npmrc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "registry" && !strings.HasSuffix(key, ":registry") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if strings.Contains(value, "${") || strings.HasPrefix(dart(value), want) {
			return true
		}
	}
	return false
}

func lockfilesOf(byManager map[string][]string, kinds []string) []string {
	var out []string
	for _, k := range kinds {
		out = append(out, sortedCopy(byManager[k])...)
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
