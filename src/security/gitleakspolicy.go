// A gitleaks config, and an ignore file, that the build-output secrets scan
// takes from the SOURCE tree.
//
// Deliberately untagged (no //go:build !unit_test), so gitleakspolicy_test.go
// can drive the path rules, the resolve script and the labels: the runner in
// secrets_source.go only fetches and mounts the files.
//
// Why the source tree and never the output. The archive scan grades a built
// directory, and a .gitleaks.toml or .gitleaksignore at that directory's root
// is honoured by gitleaks exactly as one at a repository's root is. But the
// output is the thing being graded: a file in it is shipped with the
// deployable, is written by the build rather than reviewed as code, and would
// make the bundle a co-author of its own report. A config read from the
// source tree is reviewed with the change that adds it and never ships.
//
// So the two files are resolved inside the source tree, refused when they
// escape it, copied out, and mounted OUTSIDE the scanned directory, where
// gitleaks reads them through --config and --gitleaks-ignore-path. Nothing is
// added to the output, so a finding's path is the same with or without them.
//
// When either is supplied and the output's root ALSO carries .gitleaks.toml or
// .gitleaksignore, the scan is refused rather than run. Two sources of
// acceptance cannot be read as one, and the output-root file cannot simply be
// ignored: gitleaks loads a root .gitleaksignore unconditionally (measured,
// v8.30.1: --gitleaks-ignore-path elsewhere does not stop it), so ignoring it
// would mean deleting a file from the deployable before scanning it — a
// coverage hole in the very tree this scan exists to read.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// gitleaksPolicyMount is where the supplied files are mounted, outside the
// scanned /src, so they are never part of what gitleaks reads as the output.
const (
	gitleaksPolicyMount      = "/cicd-gitleaks"
	gitleaksPolicyConfigPath = gitleaksPolicyMount + "/config.toml"
	gitleaksPolicyIgnorePath = gitleaksPolicyMount + "/gitleaksignore"
)

// gitleaksPolicy is the config and ignore file a scan was given, as paths
// relative to the source tree. The zero value is "none supplied": the scan
// then behaves byte-for-byte as it did before either existed, honouring the
// scanned tree's own root files.
type gitleaksPolicy struct {
	Config string
	Ignore string
}

func (p gitleaksPolicy) set() bool { return p.Config != "" || p.Ignore != "" }

// parseGitleaksPolicy checks both paths before any container exists. A value
// that is empty once trimmed is "not supplied", the CLI's default; anything
// else must name a file inside the source tree by a plain relative path, or
// the call fails here — never a silent no-op and never a scan that quietly ran
// on gitleaks' defaults.
func parseGitleaksPolicy(configFlag, config, ignoreFlag, ignore string) (gitleaksPolicy, error) {
	c, err := gitleaksPolicyPath(configFlag, config)
	if err != nil {
		return gitleaksPolicy{}, err
	}
	i, err := gitleaksPolicyPath(ignoreFlag, ignore)
	if err != nil {
		return gitleaksPolicy{}, err
	}
	return gitleaksPolicy{Config: c, Ignore: i}, nil
}

// gitleaksPolicyPath validates one path by its spelling. What the spelling
// cannot show — that the file exists, is a regular file, and does not reach
// outside the tree through a symlink — is checked against the tree itself by
// gitleaksPolicyResolveScript.
func gitleaksPolicyPath(flag, raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("--%s %q: %s; give a path relative to the source tree, such as .gitleaks.archive.toml", flag, raw, why)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", refuse("it contains a control character")
		}
	}
	switch {
	case strings.HasPrefix(p, "/"):
		return "", refuse("an absolute path reads from outside the source tree")
	case strings.Contains(p, `\`):
		return "", refuse(`a backslash is not a path separator here`)
	case len(p) >= 2 && p[1] == ':':
		return "", refuse("a drive letter reads from outside the source tree")
	}
	p = strings.TrimPrefix(p, "./")
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "..":
			return "", refuse("a .. segment can leave the source tree")
		case "", ".":
			return "", refuse("an empty or . segment does not name a file")
		}
	}
	return p, nil
}

// gitleaksPolicyResolveScript resolves one supplied path against the source
// tree mounted at $2 and copies the file it names to $1/$4, writing one word
// to $1/$4.status: ok, missing, dangling, escape, notfile or unreadable. It always exits
// 0, so the status — not Dagger's exec failure — says what happened.
//
// realpath is applied to the root too, because the root itself may be a
// symlink (on macOS /var is), and to the file, so a symlink anywhere in the
// path is followed before the containment test. The test is on the resolved
// path, "$root"/*, so a link to /etc/passwd, or to ../ of the tree, is an
// escape however it is spelt. realpath differs across implementations on a
// path that does not exist (BusyBox resolves it, GNU and BSD may fail), so a
// failure to resolve is read as missing, never as ok.
//
// A link whose target is not there is dangling, checked before realpath. In a
// Dagger run this is what an out-of-tree link looks like: the host directory
// is uploaded with the link but not its target, so the link arrives dangling
// and would otherwise be reported as a file that does not exist.
const gitleaksPolicyResolveScript = `set -u
out=$1 root=$2 rel=$3 name=$4
st="$out/$name.status"
mkdir -p "$out"
if ! r=$(realpath "$root" 2>/dev/null); then echo missing > "$st"; exit 0; fi
p="$r/$rel"
if [ ! -e "$p" ] && [ ! -L "$p" ]; then echo missing > "$st"; exit 0; fi
if [ -L "$p" ] && [ ! -e "$p" ]; then echo dangling > "$st"; exit 0; fi
if ! t=$(realpath "$p" 2>/dev/null); then echo missing > "$st"; exit 0; fi
case "$t" in
  "$r"/*) ;;
  *) echo escape > "$st"; exit 0 ;;
esac
if [ ! -e "$t" ]; then echo missing > "$st"; exit 0; fi
if [ ! -f "$t" ]; then echo notfile > "$st"; exit 0; fi
if ! cp "$t" "$out/$name" 2>/dev/null; then echo unreadable > "$st"; exit 0; fi
echo ok > "$st"
exit 0`

// gitleaksPolicyStatusError turns the resolve script's status into the
// reason the scan did not run, or nil for ok. An unknown status is an error
// too: a word cicd does not recognise is not a file it checked.
func gitleaksPolicyStatusError(what, rel, status string) error {
	head := "gitleaks: the " + what + " " + rel + " "
	switch strings.TrimSpace(status) {
	case "ok":
		return nil
	case "missing":
		return errors.New(head + "does not exist in the source tree, so the build output was not scanned with it, and was not scanned at all")
	case "dangling":
		return errors.New(head + "is a symbolic link whose target is not in the source tree (it points outside the tree, or at nothing); it is refused and the build output was not scanned")
	case "escape":
		return errors.New(head + "resolves, through a symlink, to a file outside the source tree; it is refused and the build output was not scanned")
	case "notfile":
		return errors.New(head + "is not a regular file in the source tree; it is refused and the build output was not scanned")
	case "unreadable":
		return errors.New(head + "could not be read from the source tree, so the build output was not scanned")
	default:
		return errors.New(head + "could not be checked (resolve status " + fmt.Sprintf("%q", strings.TrimSpace(status)) +
			"), so the build output was not scanned")
	}
}

// gitleaksPolicyCollision refuses a supplied file beside a suppression file
// at the root of the scanned output: two sources of acceptance cannot be read
// as one, and the output's own cannot be switched off without deleting it from
// the deployable (see the package note above). entries is the output root's
// Entries(); a directory carries a trailing separator and is not the file.
func gitleaksPolicyCollision(entries []string, p gitleaksPolicy, scope string) error {
	if !p.set() {
		return nil
	}
	hasConfig, hasIgnore := gitleaksSuppressionFiles(entries)
	var found []string
	if hasConfig {
		found = append(found, gitleaksConfigFile)
	}
	if hasIgnore {
		found = append(found, gitleaksIgnoreFile)
	}
	if len(found) == 0 {
		return nil
	}
	return errors.New("gitleaks: the " + scope + "'s root carries " + strings.Join(found, " and ") +
		", and a gitleaks config or ignore file was also supplied from the source tree; two sources of acceptance " +
		"cannot be reported as one, so the " + scope + " was not scanned. Remove the scanner file from the " + scope +
		" (it ships with the deployable), or stop supplying one from the source tree")
}

// gitleaksConfigExtendsPath reports whether a gitleaks config sets
// [extend] path. gitleaks resolves that path against its working directory,
// which is the scanned output (measured, v8.30.1: a relative path beside the
// config was not found, one in the scanned directory was loaded), so the
// supplied config would pull rules or an allowlist out of the very tree it
// grades. Refused rather than rewritten.
//
// A line scanner, not a TOML parser: it tracks the table header and looks for
// a path key under [extend], and for the dotted extend.path and the inline
// extend = { path = ... } spellings. A config that hides the key some other
// way still loads it, so this narrows the door, and the docs say so.
func gitleaksConfigExtendsPath(toml string) bool {
	table := ""
	for _, line := range strings.Split(toml, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") {
			end := strings.IndexByte(l, ']')
			if end < 0 {
				continue
			}
			table = strings.TrimSpace(strings.Trim(l[:end+1], "[]"))
			continue
		}
		key, val, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		switch {
		case table == "extend" && key == "path":
			return true
		case table == "" && key == "extend.path":
			return true
		case table == "" && key == "extend" && strings.Contains(val, "path"):
			return true
		}
	}
	return false
}

// gitleaksPolicyArgs is what the primary tree leg appends when files were
// supplied. Only the primary leg: the shadow runs on gitleaks' defaults with
// nothing honoured, which is what makes the difference measurable.
func gitleaksPolicyArgs(p gitleaksPolicy) []string {
	var args []string
	if p.Config != "" {
		args = append(args, "--config", gitleaksPolicyConfigPath)
	}
	if p.Ignore != "" {
		args = append(args, "--gitleaks-ignore-path", gitleaksPolicyIgnorePath)
	}
	return args
}

// gitleaksPolicyDigest is the short content digest the record line carries,
// so the evidence says not only which path was used but which version of it.
func gitleaksPolicyDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// gitleaksPolicyRecord is the warnings[] line naming what the scan was run
// with. It is written whenever a file was supplied, whatever it removed: an
// acceptance that removed nothing today is still the policy the pass rests on.
func gitleaksPolicyRecord(p gitleaksPolicy, configDigest, ignoreDigest, scope string) string {
	var with []string
	if p.Config != "" {
		with = append(with, "the config "+p.Config+" ("+configDigest+")")
	} else {
		with = append(with, "gitleaks' default rules")
	}
	if p.Ignore != "" {
		with = append(with, "the ignore file "+p.Ignore+" ("+ignoreDigest+")")
	}
	return "gitleaks: SUPPLIED POLICY — the " + scope + " was scanned with " + strings.Join(with, " and ") +
		", read from the source tree and not from the " + scope +
		"; what it removed is listed as SUPPRESSED, and a default rule it does not load as NARROWED RULES"
}

// gitleaksOrigin says where the suppression files a scan honoured came from,
// so the disclosure names them truthfully. The zero value is the scanned
// tree's own root files, and keeps every warning byte-for-byte what it was.
type gitleaksOrigin struct {
	// hasConfig is true when a config other than gitleaks' defaults applied.
	hasConfig bool
	// config and ignore are the supplied files' paths in the source tree;
	// empty means the scanned tree's root file.
	config string
	ignore string
}

// gitleaksTreeOrigin is the origin of a scan that honours the scanned tree's
// own root files.
func gitleaksTreeOrigin(hasConfig bool) gitleaksOrigin {
	return gitleaksOrigin{hasConfig: hasConfig}
}

// gitleaksSuppliedOrigin is the origin of a scan given files from the source
// tree.
func gitleaksSuppliedOrigin(p gitleaksPolicy) gitleaksOrigin {
	return gitleaksOrigin{hasConfig: p.Config != "", config: p.Config, ignore: p.Ignore}
}

// ignoreName and configName are how the disclosure names each file.
func (o gitleaksOrigin) ignoreName() string {
	if o.ignore != "" {
		return "the source tree's " + o.ignore + ", the ignore file supplied for this scan"
	}
	return gitleaksIgnoreFile
}

func (o gitleaksOrigin) configName() string {
	if o.config != "" {
		return "the source tree's " + o.config + ", the config supplied for this scan"
	}
	return "the scanned tree's " + gitleaksConfigFile
}

// narrowedSubject is the NARROWED RULES warning's subject.
func (o gitleaksOrigin) narrowedSubject(scope string) string {
	if o.config != "" {
		return "the config supplied for the " + scope + ", the source tree's " + o.config + ","
	}
	return "the " + scope + "'s " + gitleaksConfigFile
}
