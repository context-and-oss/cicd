// Which .NET SDK a consumer's own test command runs in.
//
// Untagged (no //go:build !unit_test) on purpose. byotest.go, where this used to
// live, is excluded from `make test-module-units`, and the rule below is a switch
// over which of three states a repository is in — exactly the shape that survived
// untested in lint.go and had to be moved out for the same reason.
package main

import "fmt"

// dotnetTestToolchain picks the SDK image a BYO .NET command runs in, given what
// the tree asked of the SDK and what a root global.json said.
//
// The BYO leg used to resolve through ResolveToolchainDetail, which reads
// global.json and nothing else, so a repository with no global.json landed on the
// pinned 8.0 default whatever it targeted. Measured on a consumer whose projects
// declare net10.0: every project failed with `error NETSDK1045: The current .NET
// SDK does not support targeting .NET 10.0`, the coverage harvest then found no
// results directory to read at all, and the envelope named neither the SDK nor
// why it had been chosen — an absent version file carries no Note, so the leg
// reported `test command failed (exit 1)` and nothing more. cicd had read
// `<TargetFramework>net10.0</TargetFramework>` out of that same tree earlier in
// the same run: lint.go and test.go resolve the band through dotnetResolveBand,
// and this was the one .NET path that did not.
//
// The image is the readable tag, not the digest-pinned dotnetSDK*Image that
// dotnetSDKBase hands the Check legs. That is ADR-004 level 3 on purpose — the
// container a *consumer's* command runs in is resolved at run time and belongs to
// them — and pinning it here would move a consumer's test runner onto a digest
// cicd bumps on its own schedule. The band was what was wrong, so the band is
// what moves.
func dotnetTestToolchain(req dotnetBandRequest, globalJSON versionFileRead) ToolchainResolution {
	band, bandNote := dotnetResolveBand(req)
	res := ToolchainResolution{Image: dotnetSDKLabelFor(band), From: ToolchainFromDefault}
	switch req.Source {
	case dotnetBandSourceGlobalJSON:
		res.From = ToolchainFromGlobalJSON
	case dotnetBandSourceTFM:
		res.From = ToolchainFromTargetFramework
	}

	switch {
	case req.Band != "" && band != req.Band:
		// The repository asked for a band cicd pins no image of. dotnetResolveBand
		// already wrote the sentence saying which band ran instead and why, and it
		// is the same sentence the Check legs disclose, so it is passed through
		// rather than restated — two wordings of one fact drift.
		res.Note = bandNote
	case req.Band == "":
		// Nothing in the tree decided the band. A version file that is present and
		// says nothing usable still has to say so: the measured case is a
		// global.json carrying only a Microsoft.Testing.Platform runner opt-in,
		// which declares no sdk.version and cannot be honoured by the 8.0 band that
		// predates it. dotnetBandRequest records what was *requested*, so it cannot
		// make this disclosure on its own — an unreadable file and an absent one
		// both reach here as no request.
		if globalJSON.Present && globalJSON.Value == "" {
			res.Note = fmt.Sprintf(
				"global.json %s, and no literal TargetFramework decided it either, so the pinned default %s was used instead",
				globalJSON.Why, res.Image)
		}
	}
	return res
}
