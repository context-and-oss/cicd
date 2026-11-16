// The SAST engine: Opengrep, pinned by release version and per-architecture
// sha256, run on a digest-pinned Python base.
//
// Why Opengrep and not Semgrep OSS. Measured against the same probes on both:
// Semgrep OSS 1.162 and 1.185 reject C# 12 primary constructors and C# 14
// null-conditional assignment, and skip a C# record declaration with no
// notification at all, so a C# tree was read less completely than its file
// count said and nothing in the SARIF could tell. Opengrep 2.0.0 parses every
// one of those probes, and a file it genuinely cannot parse is still reported
// as a PartialParsing notification in the same shape semgrepnotifications.go
// already reads. Opengrep 1.x is not a substitute: it drops a broken file
// silently, which is the exact failure this swap exists to close. Rules,
// packs, .semgrepignore and nosemgrep comments are unchanged — Opengrep reads
// the Semgrep rule language and honours both nosemgrep and noopengrep.
//
// Why a binary and not an image. Opengrep publishes self-contained release
// binaries, not a container image, so the pin is the same shape as
// zapaddons.go one level down: a readable version, the URL built from it, and
// the content digest GitHub publishes for each asset. The base image is the
// same python:3.12-slim pin quality.Check uses, because the scan script's
// helpers (semgrep_*.py) need python3 and nothing else.
//
// The digest is checked in the container, before the binary is executed, and
// a mismatch is a non-run — never a scan with an unverified engine. The same
// holds for the one Python package the helpers need; see pyyamlVersion. Dagger's
// own File.Digest is documented as unstable across engine releases, so it is
// not a content hash this repository can pin against; sha256sum is.
//
// To bump: change opengrepVersion, take each asset's sha256 from the release
// page (or download it and run sha256sum), and replace both digests. Renovate
// proposes the version alone; a bump PR that forgets a digest fails every scan
// on that architecture with PINNED DOWNLOAD REJECTED, which is the point.
//
// Deliberately untagged: the unit-test build must see the selection and the
// status vocabulary.
package main

import (
	"errors"
	"strconv"
	"strings"
)

const (
	// renovate: datasource=github-releases depName=opengrep/opengrep
	opengrepVersion = "2.0.0"
	opengrepRelease = "https://github.com/opengrep/opengrep/releases/download/v" + opengrepVersion + "/"

	opengrepAMD64Asset  = "opengrep_linux_x86"
	opengrepAMD64SHA256 = "37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0"
	opengrepARM64Asset  = "opengrep_linux_aarch64"
	opengrepARM64SHA256 = "6257b65423a744b704af2ff9beeb8f222c2f6925236af386b56b031d4c06d6d8"

	// PyYAML, for the two helpers that read upstream rule YAML
	// (semgrep_gha.py, semgrep_inline.py). The Semgrep image bundled it; the
	// slim Python base does not, and a helper whose import fails is a non-run
	// on exactly the scans that need it — the GitHub Actions fallback and
	// inline JavaScript — while every other scan stays green. So it is pinned
	// beside the engine, by wheel and digest (PyPI's published sha256), and
	// installed with --no-index from the verified file: pip resolves nothing
	// and fetches nothing. cp312 because pythonImage is 3.12; a base bump
	// across a minor needs these wheels changed with it, and the install
	// failing is what says so.
	pyyamlVersion     = "6.0.3"
	pyyamlAMD64Wheel  = "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
	pyyamlAMD64URL    = "https://files.pythonhosted.org/packages/8b/9d/b3589d3877982d4f2329302ef98a8026e7f4443c765c46cfecc8858c6b4b/" + pyyamlAMD64Wheel
	pyyamlAMD64SHA256 = "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc"
	pyyamlARM64Wheel  = "pyyaml-6.0.3-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl"
	pyyamlARM64URL    = "https://files.pythonhosted.org/packages/ed/23/7a778b6bd0b9a8039df8b1b1d80e2e2ad78aa04171592c8a5c43a56a6af4/" + pyyamlARM64Wheel
	pyyamlARM64SHA256 = "9149cad251584d5fb4981be1ecde53a1ca46c891a79788c0df828d2f166bda28"

	// Where the pinned files are placed, and where the script records whether
	// they matched. Outside /src and /tmp/report.*, so neither the scanned tree
	// nor a report can stand in for any of them.
	opengrepBinPath    = "/usr/local/bin/opengrep"
	pyyamlWheelDir     = "/opt/cicd-wheels"
	opengrepVerifyPath = "/tmp/opengrep.verify"
	// The expected digests and the wheel path reach the script as environment
	// variables set from the constants above, never from consumer input.
	opengrepSHA256Env = "CICD_OPENGREP_SHA256"
	pyyamlSHA256Env   = "CICD_PYYAML_SHA256"
	pyyamlWheelEnv    = "CICD_PYYAML_WHEEL"
)

// opengrepAssets is what one platform needs fetched and verified.
type opengrepAssets struct {
	BinURL, BinSHA256                string
	WheelURL, WheelName, WheelSHA256 string
}

// WheelPath is where the wheel is placed in the container. pip reads the
// platform tags from the filename, so the file keeps its published name.
func (a opengrepAssets) WheelPath() string { return pyyamlWheelDir + "/" + a.WheelName }

// opengrepAssetsFor picks the pinned release assets for the engine's platform.
//
// An unknown platform is an error, not a fallback to the other architecture:
// an x86 binary under emulation on an arm engine would run, slowly, and an
// arm binary on an x86 engine would not run at all — and either way the
// digest pinned for one asset says nothing about the other.
func opengrepAssetsFor(platform string) (opengrepAssets, error) {
	p := strings.TrimSpace(platform)
	// A platform may carry a variant (linux/arm64/v8); only os/arch decide.
	if parts := strings.Split(p, "/"); len(parts) >= 2 {
		p = parts[0] + "/" + parts[1]
	}
	switch p {
	case "linux/amd64":
		return opengrepAssets{
			BinURL: opengrepRelease + opengrepAMD64Asset, BinSHA256: opengrepAMD64SHA256,
			WheelURL: pyyamlAMD64URL, WheelName: pyyamlAMD64Wheel, WheelSHA256: pyyamlAMD64SHA256,
		}, nil
	case "linux/arm64":
		return opengrepAssets{
			BinURL: opengrepRelease + opengrepARM64Asset, BinSHA256: opengrepARM64SHA256,
			WheelURL: pyyamlARM64URL, WheelName: pyyamlARM64Wheel, WheelSHA256: pyyamlARM64SHA256,
		}, nil
	}
	return opengrepAssets{}, errors.New("opengrep: no pinned " + opengrepVersion + " binary for engine platform " +
		strconv.Quote(platform) + "; cicd pins linux/amd64 and linux/arm64 only, so SAST did not run")
}

// The answers the script can write about each pinned file. Four, for the
// reason zapaddons.go gives: "absent", "unreadable" and "the wrong bytes" are
// different facts with remedies in different places, and only the last one is
// a supply-chain event. The wheel has a fifth: verified, and pip still would
// not install it.
const (
	opengrepVerifyOK            = "ok"
	opengrepVerifyMissing       = "missing"
	opengrepVerifyMismatch      = "mismatch"
	opengrepVerifyUnreadable    = "unreadable"
	opengrepVerifyUninstallable = "uninstallable"
)

// opengrepVerifyScript runs before anything else in semgrepScript and writes
// "<binary status> <wheel status>". On anything but "ok ok" it writes exit 2
// and an empty report and stops, so the classification in sast.go sees a
// non-run; opengrepVerifyError then names which one. The wheel is installed
// only after its digest matched, from the file, with no index.
const opengrepVerifyScript = `cicd_check() {
  if [ ! -e "$1" ]; then echo ` + opengrepVerifyMissing + `
  elif [ ! -r "$1" ]; then echo ` + opengrepVerifyUnreadable + `
  else
    got=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$got" ]; then echo ` + opengrepVerifyUnreadable + `
    elif [ "$got" = "$2" ]; then echo ` + opengrepVerifyOK + `
    else echo ` + opengrepVerifyMismatch + `; fi
  fi
}
cicd_bin=$(cicd_check ` + opengrepBinPath + ` "${` + opengrepSHA256Env + `:-}")
cicd_whl=$(cicd_check "${` + pyyamlWheelEnv + `:-}" "${` + pyyamlSHA256Env + `:-}")
if [ "$cicd_whl" = ` + opengrepVerifyOK + ` ]; then
  python3 -m pip install --quiet --no-deps --no-index --no-cache-dir --disable-pip-version-check \
    --root-user-action=ignore "$` + pyyamlWheelEnv + `" >/dev/null 2>&1 || cicd_whl=` + opengrepVerifyUninstallable + `
fi
echo "$cicd_bin $cicd_whl" > ` + opengrepVerifyPath + `
if [ "$cicd_bin $cicd_whl" != "` + opengrepVerifyOK + ` ` + opengrepVerifyOK + `" ]; then
  echo 2 > /tmp/semgrep.exit
  : > /tmp/report.sarif
  exit 0
fi
`

// opengrepVerifyError turns what the script wrote into the error the
// envelope carries, or "" when both files matched their pins.
//
// An unrecognised or empty answer is "missing", never "mismatch": a status
// cicd cannot read must not manufacture a supply-chain accusation.
func opengrepVerifyError(raw string, a opengrepAssets) string {
	fields := strings.Fields(raw)
	for len(fields) < 2 {
		fields = append(fields, "")
	}
	if msg := verifyFailure("the opengrep "+opengrepVersion+" binary", a.BinURL, a.BinSHA256, fields[0]); msg != "" {
		return msg
	}
	return verifyFailure("PyYAML "+pyyamlVersion+", which cicd's rule helpers need", a.WheelURL, a.WheelSHA256, fields[1])
}

func verifyFailure(what, url, sha256, status string) string {
	switch status {
	case opengrepVerifyOK:
		return ""
	case opengrepVerifyMismatch:
		return "opengrep: PINNED DOWNLOAD REJECTED — " + what + " fetched from " + url +
			" did not match its pinned sha256 (" + sha256 + "), so cicd did not use it and SAST did not run. " +
			"Either the pin is stale or the file was substituted; do not read this scan as clean until it is resolved."
	case opengrepVerifyUnreadable:
		return "opengrep: cicd placed " + what + " in the scan container and could not read it back, so its " +
			"digest was never checked and SAST did not run. That is cicd's own plumbing; nothing here says the bytes were wrong."
	case opengrepVerifyUninstallable:
		return "opengrep: " + what + " matched its pinned sha256 and pip would not install it on " + pythonImage +
			", so SAST did not run. The wheel's Python tag no longer fits the base image; bump them together."
	default:
		return "opengrep: " + what + " from " + url + " was not in the scan container, so SAST did not run."
	}
}
