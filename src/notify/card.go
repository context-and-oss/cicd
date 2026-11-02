// Teams adaptive-card model and builder.
//
// Untagged like render.go so `go test -tags unit_test` can drive the whole
// card → JSON → HTTP path in delivery_test.go. The Dagger entry functions that
// consume it (Teams, BuildCard) stay in teams.go behind `//go:build !unit_test`.

package main

import (
	"fmt"
)

type teamsCard struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string        `json:"contentType"`
	Content     teamsCardBody `json:"content"`
}

type teamsCardBody struct {
	Type    string        `json:"type"`
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Body    []teamsBlock  `json:"body"`
	Actions []teamsAction `json:"actions,omitempty"`
}

type teamsBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Weight   string `json:"weight,omitempty"`
	Size     string `json:"size,omitempty"`
	Color    string `json:"color,omitempty"`
	IsSubtle bool   `json:"isSubtle,omitempty"`
	Wrap     bool   `json:"wrap,omitempty"`
}

type teamsAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

func buildTeamsCard(pipelineName, runUrl string, env *envelope) teamsCard {
	status := headline(env)
	color := cardColor(env)
	// The two backticks below are NOT render.go's codeSpan fix, and this card is
	// not covered by it. An Adaptive Cards TextBlock renders a documented
	// *subset* of markdown — bold, italic, lists, hyperlinks — and code spans are
	// not in it. So these backticks are decoration that renders literally; they
	// have never fenced anything, and adding cellCode here would add more of
	// them without removing anything. The question on this surface is [text](url),
	// which IS in the subset.
	//
	// It is a live question for the Commit row and a closed one for the Branch
	// row, and the difference is where each value comes from:
	//
	//   - Branch is a git refname, and git refuses a refname containing '[' —
	//     check-ref-format rejects feat/a[b, along with '*', '~', '^', ':', '?'
	//     and a space. It accepts a backtick, '|', '<' and '&', which is exactly
	//     why render.go had to change; it does not accept the one character a
	//     markdown link must start with. No link can be formed here.
	//
	//   - CommitSHA is not a refname and is not produced by cicd. It is the
	//     --commit-sha string, unvalidated anywhere in this module (schema.go
	//     declares it as a bare string), so check-ref-format says nothing about
	//     it and '[' reaches this TextBlock intact.
	//
	// Under what cicd ships the workflows pass ${{ github.sha }}, so there is no
	// attacker-controlled path to that field today and this is not a live
	// exploit. It is an unguarded sink whose guard was a false premise: an
	// earlier revision of this comment closed the whole card on "every field is
	// cicd-produced or a refname", which is untrue of exactly one field, and a
	// consumer wiring a tag, a version string or any other free value into
	// --commit-sha would inherit a link sink with nothing here objecting.
	//
	// Not fixed in this change, deliberately and with the reason recorded rather
	// than assumed. Every claim in render.go's fix is checkable against
	// CommonMark, which the tests do; a fix here is a claim about a renderer no
	// test in this repository is allowed to contact (no CI job posts to Teams —
	// see the outbound-protocols rule in CLAUDE.md). It also needs a decision
	// this change has no business making silently: refuse a commit value that
	// cannot be a commit identifier, or escape for a parser we cannot drive.
	// Refusal is the house answer (resolveIncludeNames) and it is a behaviour
	// change on a delivery path. Tracked, not deferred by silence.
	//
	// The emphasis residue is unchanged and is genuinely cosmetic: '_' is legal
	// in a refname, so a branch name carrying one may render italic. It cannot
	// carry a destination.
	body := []teamsBlock{
		{Type: "TextBlock", Text: fmt.Sprintf("**%s** — %s", pipelineName, status), Weight: "Bolder", Size: "Medium", Color: color},
		{Type: "TextBlock", Text: fmt.Sprintf("Commit: `%s`", env.Repo.CommitSHA), IsSubtle: true, Wrap: true},
		{Type: "TextBlock", Text: fmt.Sprintf("Branch: `%s`", env.Repo.Branch), IsSubtle: true},
		{Type: "TextBlock", Text: fmt.Sprintf("Findings: %s | Time: %s", humanCount(env.FindingsCount), formatDuration(env.DurationMS)), IsSubtle: true},
	}
	var actions []teamsAction
	if runUrl != "" {
		actions = append(actions, teamsAction{Type: "Action.OpenUrl", Title: "View run", URL: runUrl})
	}
	return teamsCard{
		Type: "message",
		Attachments: []teamsAttachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content: teamsCardBody{
				Type:    "AdaptiveCard",
				Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
				Version: "1.2",
				Body:    body,
				Actions: actions,
			},
		}},
	}
}

// cardColor picks the card's accent from the gate verdict AND the outcome, for
// the same reason headline carries both. A card titled "Passed · ⚠️ errored"
// rendered in green still tells a reader at a glance that everything is fine,
// and the colour is the part of a Teams notification that gets read first.
func cardColor(env *envelope) string {
	if !env.Passed {
		return "Attention"
	}
	switch env.Outcome {
	case OutcomeFailed, OutcomeError:
		return "Attention"
	case OutcomeFindings:
		return "Warning"
	default:
		return "Good"
	}
}
