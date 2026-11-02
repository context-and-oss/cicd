// The passive-scan rules cicd pins, and why the packaged scan is stopped from
// fetching its own.
//
// The packaged scans start ZAP with `-addonupdate -addoninstall pscanrulesBeta`
// unless `-silent` appears in the -z options (zap-baseline.py:435, and
// unconditionally in zap-api-scan.py:349, which has no automation-framework
// branch to take instead). Two things follow from that, and the second is what
// broke a run.
//
// The pin governs almost nothing. Measured against the pinned image
// (ghcr.io/zaproxy/zaproxy 2.17.0, index digest 8d387b1a…) on 2026-09-16: one
// baseline scan downloaded **73** add-ons from the ZAP marketplace before it
// looked at the target, replacing network-beta-0.28.0 with 0.29.0 and
// pscanrules-release-74 with 75 — neither of which is pinned anywhere. Two runs
// of the same digest on different days therefore run different scan rules, and a
// finding that appears or disappears between them cannot be attributed. It is
// also 73 pieces of executable code arriving from the internet into a security
// scanner, on every run.
//
// And the update races the scanner's own socket. `network` is the add-on that
// owns ZAP's main proxy; upgrading it inside the running daemon reloads
// ExtensionNetwork, and the replacement binds while the outgoing instance still
// holds the port. From the run that failed — the two lines are 5 ms apart:
//
//	30106 INFO  CommandLine      - Add-on downloaded to: /home/zap/.ZAP/plugin/network-beta-0.29.0.zap
//	30111 WARN  ExtensionNetwork - Failed to start the main proxy: java.net.BindException Address already in use
//	30112 ERROR CommandLine      - Terminating ZAP, unable to start the main proxy.
//
// That is port-independent: the collision is with ZAP's own outgoing listener,
// so it would happen on a port get_free_port() drew exactly as on a pinned one.
// See zapProxyPort, which was written believing otherwise.
//
// So `-silent` goes in — and then the rules it costs are put back from a pin
// rather than lost. Measured, same image, same target, three runs:
//
//	                                 add-ons downloaded   rules run
//	today (no -silent)                              73          67
//	-silent alone                                    0          61
//	-silent + the add-on below                       0          67
//
// The third is rule-for-rule identical to the first. The six rules `-silent`
// alone costs are zapBetaPassiveRules, all of them in pscanrulesBeta and none in
// the pscanrules-release the image ships; Source Code Disclosure and
// Permissions Policy Header Not Set both fired on the measurement target, so the
// loss is not theoretical.
//
// Deliberately untagged (no //go:build !unit_test): none of this needs Dagger.
package main

import "strings"

// The pinned pscanrulesBeta add-on.
//
// Not in images.go and not an `// renovate-image:` triple: it is a release
// asset, not an image, and check-runtime-image-pins.py reads that file for
// From() references. The shape is the same idea one level down — a readable
// version, the URL built from it, and an immutable content digest — so that the
// thing cicd loads is fixed by this repository and not by whatever the
// marketplace is serving this month.
//
// To bump it: change zapPscanRulesBetaVersion, download the asset at
// zapPscanRulesBetaURL, and put its sha256 here. A mismatch is a hard failure,
// never a quiet skip — see zapAddOnStatusMismatch.
const (
	zapPscanRulesBetaVersion = "50"
	zapPscanRulesBetaFile    = "pscanrulesBeta-beta-" + zapPscanRulesBetaVersion + ".zap"
	zapPscanRulesBetaURL     = "https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesBeta-v" +
		zapPscanRulesBetaVersion + "/" + zapPscanRulesBetaFile
	// Verified against the copy the packaged scan installs itself: the
	// marketplace asset and the release asset are byte-identical (596,114
	// bytes, same digest), so this pins exactly what an unpinned run would
	// have fetched.
	zapPscanRulesBetaSHA256 = "a979f7cd5d8be10e0338b417e006ec1e2f6ec79101010d570ddb5199892e921b"
)

// zapSilentOption is what stops the packaged scan updating add-ons.
//
// `-silent` is ZAP's own flag — "Ensures ZAP does not make any unsolicited
// requests, including check for updates" — and the packaged scans test for the
// literal string in the -z value rather than taking a flag of their own, so it
// has to travel through -z. It also silences the call-home add-on, whose
// "ExtensionCallHome - Read timed out" is the same machinery failing louder.
const zapSilentOption = "-silent"

// zapBetaPassiveRules is what pscanrulesBeta contributes, by ZAP plugin id.
//
// Measured by diffing the packaged scan's own rule list across the three runs
// in this file's header, not read from the add-on's manifest: the manifest
// would say what upstream ships, and this says what actually ran.
var zapBetaPassiveRules = []string{
	"10026 HTTP Parameter Override",
	"10049 Content Cacheability",
	"10063 Permissions Policy Header Not Set",
	"10099 Source Code Disclosure",
	"10110 Dangerous JS Functions",
	"90004 Cross-Origin-Resource-Policy Header Missing or Invalid",
}

// The answers zapRunScript can write about the pinned add-on.
//
// Four and not two. "Absent" and "the wrong bytes" are opposite facts — a fetch
// that did not happen against a fetch that returned something else — and
// collapsing them would let a substituted artifact read as a network blip.
//
// The fourth was measured, not foreseen. `sha256sum` answers the same exit
// status for a file whose digest differs and a file it could not open, and the
// first smoke run of this code hit the second: Dagger mounts an HTTP file
// 0600 root:root, the pinned image runs as uid 1000, so `[ -f ]` was true, the
// read failed, and the envelope carried PINNED ADD-ON REJECTED — the loudest
// error in this file, naming a supply-chain substitution that had not happened,
// about an artifact whose bytes were in fact correct. A reader would have gone
// looking at GitHub's release assets. The mount is fixed (see runZAP), and the
// status stays, because the shell must not be able to report a permission
// problem as an attack again.
const (
	zapAddOnStatusOK         = "ok"
	zapAddOnStatusMissing    = "missing"
	zapAddOnStatusMismatch   = "mismatch"
	zapAddOnStatusUnreadable = "unreadable"
)

// zapAddOnWarning fires when the pinned rules did not load and nothing was
// substituted for them.
//
// A warning, not an error: the scan ran, and 61 of its 67 rules are exactly the
// rules they would have been. But never silent, because the alternative is a
// smaller rule set rendering identically to a complete one — the founding
// failure of this repository, arriving through the door marked "the download
// didn't work".
//
// Both causes say the same consequence and then part company on the cause,
// because the remedies are in different repositories: an add-on that never
// arrived is a fetch to look at, an add-on cicd could not read is cicd's own
// plumbing and nobody should go hunting upstream for it.
func zapAddOnWarning(status string) string {
	var why string
	switch status {
	case zapAddOnStatusMissing:
		why = "cicd could not place its pinned " + zapPscanRulesBetaFile +
			" in the scan container"
	case zapAddOnStatusUnreadable:
		why = "cicd staged its pinned " + zapPscanRulesBetaFile + " in the scan " +
			"container and then could not read it back, so the digest was never " +
			"checked and the file was never installed. That is cicd's own plumbing, " +
			"not the artifact: nothing here says the bytes were wrong"
	default:
		return ""
	}
	return "dast: PASSIVE RULES REDUCED — " + why + ", so the scan ran without " +
		"pscanrulesBeta and these rules did not run: " + strings.Join(zapBetaPassiveRules, "; ") +
		". Every other rule ran normally; this narrows what was looked for, not what was found."
}

// zapAddOnError fires when the pinned add-on arrived with the wrong bytes.
//
// An error, and the scan's own result is not the reason. cicd asked for a
// specific artifact by digest and was handed a different one; that is a
// supply-chain event, and the one response that is never acceptable is loading
// it into the scanner and reporting whatever it says.
func zapAddOnError(status string) string {
	if status != zapAddOnStatusMismatch {
		return ""
	}
	return "dast: PINNED ADD-ON REJECTED — " + zapPscanRulesBetaFile + " did not match its pinned " +
		"sha256 (" + zapPscanRulesBetaSHA256 + "), so cicd removed it rather than load unverified " +
		"code into the scanner. Fetched from " + zapPscanRulesBetaURL + ". Either the pin is stale " +
		"or the artifact was substituted; the scan below ran without pscanrulesBeta and must not be " +
		"read as a complete passive scan until this is resolved."
}

// zapAddOnStatus normalises what zapRunScript wrote.
//
// An unrecognised answer becomes "missing" rather than being passed through: a
// status cicd cannot read means cicd does not know whether six rules ran, and
// the only safe reading of "I don't know" is the one that discloses. Neither
// "mismatch" nor "unreadable" is ever reached this way, so a truncated status
// file can never manufacture a supply-chain accusation, and it cannot
// manufacture the plumbing excuse for one either.
func zapAddOnStatus(raw string) string {
	switch strings.TrimSpace(raw) {
	case zapAddOnStatusOK:
		return zapAddOnStatusOK
	case zapAddOnStatusMismatch:
		return zapAddOnStatusMismatch
	case zapAddOnStatusUnreadable:
		return zapAddOnStatusUnreadable
	default:
		return zapAddOnStatusMissing
	}
}
