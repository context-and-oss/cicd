// Teams delivery classification: whether a webhook was configured at all,
// whether a card was attempted, and whether it arrived — as evidence rather
// than as a line on stderr.
//
// This file carries no build tag on purpose. The Dagger entry function lives in
// teams.go behind `//go:build !unit_test`, so `go test -tags unit_test`
// compiles the rules below plus teamsdelivery_test.go without needing a
// generated Dagger SDK — while production executes exactly these functions.
// The rule that matters most here (a blank webhook is not a webhook) was
// unreachable from any test while it lived inside the tagged entry function,
// which is how it came to be `!= nil` in three composites and nothing else.
package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// moduleName and moduleStage identify this module in every envelope it
	// produces. They live in this untagged file, not beside the Dagger entry
	// functions, so `go test -tags unit_test` can assert on the document a
	// consumer actually receives.
	moduleName  = "notify"
	moduleStage = "cross-cutting"

	teamsToolName    = "teams"
	teamsToolVersion = "v1"

	// teamsMinScrubLen is the shortest URL fragment worth registering as a
	// secret. Below it, ReplaceAll would splice "***" through unrelated text —
	// a path of "/" would hit every slash in the message — while protecting
	// nothing a token-bearing webhook path could ever look like. A real Teams
	// incoming webhook path is roughly a hundred characters.
	teamsMinScrubLen = 16
)

// teamsScrubValues lists the values that must never reach an error string, a
// log line or the evidence envelope for this webhook.
//
// The whole URL is the obvious entry. The path is the load-bearing one: a Teams
// incoming webhook carries its token in the path, and the thing that answers a
// failed POST is often not Teams — a proxy, a WAF or a 404 page quotes the
// request *target* rather than the URL cicd sent ("The requested URL
// /webhookb2/<token>/… was not found on this server"). That body is quoted into
// the warning, and the warning now travels to combined-evidence.json and the
// pull request comment, so a fragment nobody registered would be a credential
// published one channel wider than the stderr line it replaced.
func teamsScrubValues(webhookURL string) []string {
	values := []string{webhookURL}
	parsed, err := url.Parse(webhookURL)
	if err != nil {
		return values
	}
	for _, fragment := range []string{parsed.EscapedPath(), parsed.Path, parsed.RawQuery} {
		if len(fragment) >= teamsMinScrubLen {
			values = append(values, fragment)
		}
	}
	return values
}

// newTeamsDelivery builds the outbound seam with every fragment of the webhook
// registered for scrubbing. Production and tests both go through it, so a leak
// a test cannot see is a leak production does not have either.
func newTeamsDelivery(webhookURL string) *delivery {
	return newDelivery(teamsScrubValues(webhookURL)...)
}

// teamsUnconfiguredWarning is the record for a webhook that was passed and is
// not a webhook.
//
// It is a warning and not an error because nothing went wrong: a consumer who
// never set the secret asked for no notification and got none. What it must not
// do is stay silent, because the *attempt* was already silent — an empty URL
// produced `Post "": unsupported protocol scheme ""` on stderr inside a
// twenty-minute log, and a run that never notified anybody reported success.
//
// The reason is quoted rather than summarised into "empty", because the two
// non-configurations do not look alike to whoever has to fix them: an empty
// value means the secret is not set, an unexpanded macro means the variable
// name in the pipeline does not exist.
func teamsUnconfiguredWarning(reason string) string {
	return fmt.Sprintf("teams: NOT CONFIGURED — a --teams-webhook was passed but %s, so no "+
		"card was sent and none was attempted. A secret the repository never defines still "+
		"arrives as a non-nil Secret (GitHub Actions `secrets: inherit`, Azure DevOps "+
		"`$(TEAMS_WEBHOOK)`), so \"a webhook was passed\" is not \"a webhook was configured\". "+
		"Set the TEAMS_WEBHOOK secret to a Microsoft Teams incoming-webhook URL, or stop "+
		"passing --teams-webhook.", reason)
}

// teamsNotDeliveredWarning is the record for a webhook that was configured and
// whose card did not arrive.
//
// This is the case the whole change exists for. An unconfigured channel is a
// channel nobody is relying on; a configured one that has been rotated, revoked
// or re-pointed keeps returning green runs to a team that believes it is being
// told. The detail is whatever the delivery seam produced, which is already
// scrubbed of the webhook URL by delivery.errorf/redactURL — the URL *is* the
// credential.
func teamsNotDeliveredWarning(pipelineName string, err error) string {
	return fmt.Sprintf("teams: NOT DELIVERED — the %s card was not posted: %v. The run's "+
		"verdict is unaffected and is in this evidence; the channel it was meant to reach heard "+
		"nothing. A rotated, revoked or re-pointed incoming webhook fails exactly this way, and "+
		"the card before this one may have been the last that arrived.", pipelineName, err)
}

// teamsUnconfiguredMacro matches the whole of an Azure DevOps macro that was
// never expanded. Anchored at both ends and never a substring search: a real
// incoming-webhook URL may legally carry a `$(` in a query value, and treating
// that as "not configured" would silence a channel that works.
var teamsUnconfiguredMacro = regexp.MustCompile(`^\$\([A-Za-z_][A-Za-z0-9_.]*\)$`)

// teamsUnconfiguredReason answers whether a webhook value is a configuration.
// The empty string means it is, and the value is attempted; anything else is
// the clause teamsUnconfiguredWarning quotes.
//
// Trim first: a secret file or a pipeline variable that holds only a newline is
// the same non-configuration as an empty one, and `Post "\n"` fails with the
// same unreadable transport error.
//
// The macro case is the same fault arriving through Azure DevOps rather than
// GitHub Actions. ADO expands `$(TEAMS_WEBHOOK)` before the shell parses the
// line, and an *undefined* variable expands to its own literal text — so a
// pipeline that never declared the variable hands cicd the literal text
// `$(TEAMS_WEBHOOK)`, which is not empty. This is the same fault the --include work
// recorded for --include, where quality.Check failed a run naming an
// unexpanded macro as an unknown language. The templates guard it before the
// flag is built (see templates/azure-devops/*.yml); this is the second line,
// for a consumer whose pipeline cicd did not write. Without it the run would
// report NOT DELIVERED — telling a team their webhook is broken when in truth
// they never had one, which is a worse answer than the silence it replaced.
//
// Everything else is treated as configured and is attempted: a malformed URL is
// a broken configuration, not an absent one, and the difference between the two
// is the entire point of this file, so a value that is present and wrong must
// reach teamsNotDeliveredWarning rather than be quietly reclassified as "you
// never set it up".
func teamsUnconfiguredReason(raw string) string {
	value := strings.TrimSpace(raw)
	switch {
	case value == "":
		return "resolved to an empty value"
	case teamsUnconfiguredMacro.MatchString(value):
		return fmt.Sprintf("resolved to %q, the literal text an undefined Azure DevOps "+
			"pipeline variable expands to", value)
	}
	return ""
}

// deliverTeamsCard posts the card, unless there is no webhook to post it to.
//
// Returns whether delivery was attempted, the reason it was not when it was
// not, and the delivery error when it was. attempted=false is the unconfigured
// case and is the one state in which no HTTP request leaves this process at
// all.
func deliverTeamsCard(ctx context.Context, d *delivery, webhookURL string, card teamsCard) (bool, string, error) {
	if reason := teamsUnconfiguredReason(webhookURL); reason != "" {
		return false, reason, nil
	}
	return true, "", d.postTeamsCard(ctx, webhookURL, card)
}

// teamsEvidence assembles the delivery envelope.
//
// Passed is true in all three states, deliberately. A notification is not a
// gate: the scan's verdict is what it was before the POST, and turning a
// webhook outage into a red pipeline teaches a team to stop passing the webhook
// — which is the failure this change is removing, arrived at from the other
// side. The statement therefore lives in Warnings[], which
// cross-cutting/evidence propagates into combined-evidence.json and notify
// renders into the pull request comment; genericReport would not survive the
// merge, and stderr did not survive a reader.
//
// Outcome still tells the three states apart for anything folding the run:
// CLEAN delivered, SKIPPED not configured, ERROR attempted and lost.
func teamsEvidence(
	start time.Time,
	repo repoContext,
	pipelineName string,
	attempted bool,
	unconfiguredReason string,
	deliverErr error,
) *envelope {
	env := &envelope{
		SchemaVersion: evidenceSchemaVersion,
		ModuleName:    moduleName,
		Stage:         moduleStage,
		Tool: toolInfo{
			Name:    teamsToolName,
			Version: teamsToolVersion,
			Args: []string{
				"pipeline=" + pipelineName,
				fmt.Sprintf("configured=%t", attempted),
				fmt.Sprintf("delivered=%t", attempted && deliverErr == nil),
			},
		},
		Repo:         repo,
		TimestampUTC: start.UTC(),
		DurationMS:   time.Since(start).Milliseconds(),
		Passed:       true,
	}

	switch {
	case !attempted:
		env.Outcome = OutcomeSkipped
		env.Warnings = []string{teamsUnconfiguredWarning(unconfiguredReason)}
	case deliverErr != nil:
		env.Outcome = OutcomeError
		env.Warnings = []string{teamsNotDeliveredWarning(pipelineName, deliverErr)}
	default:
		env.Outcome = OutcomeClean
	}
	return env
}
