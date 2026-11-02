//go:build !unit_test

// The audit tail every composite ends in: aggregate, deliver the Teams card,
// aggregate again with the delivery record, render the pull request comment.
//
// The same file exists in src/composites/commit, src/composites/precommit and
// src/composites/dast, because Dagger modules share no Go. Keep them
// byte-identical apart from the SDK import (scripts/repo-inventory.json
// synced_files refuses any other drift): each composite used to carry its own
// copy of this tail, and the copy that skips the second Wrap is the one that
// silently stops sending cards.
//
// Tagged: every line here is a dag call, and the generated SDK panics outside
// a session. What it decides is one branch on whether a webhook was given.
package main

import "dagger/precommit/internal/dagger"

// auditOpts carries the provenance and notification parameters a composite's
// entry function passes into finishAudit.
type auditOpts struct {
	commitSha    string
	branch       string
	repoUrl      string
	runUrl       string
	teamsWebhook *dagger.Secret
}

// finishAudit aggregates evidence files into the audit directory, posts an
// optional Teams notification, and renders the PR comment into comment.md.
func finishAudit(evidenceFiles []*dagger.File, pipeline string, opts auditOpts) *dagger.Directory {
	auditDir := dag.Evidence().Wrap(
		evidenceFiles,
		opts.commitSha, opts.branch, opts.repoUrl,
	)

	// The Teams delivery is evidence like any other leg. Whether a card was
	// sent, skipped because no webhook was configured, or lost on the way has
	// to survive into combined-evidence.json and the pull request comment —
	// not just into stderr, where `unsupported protocol scheme ""` sat inside a
	// twenty-minute log while every run reported success. notify.Teams
	// therefore returns an envelope, and the run is aggregated a second time
	// with it appended.
	//
	// That second Wrap is also what *performs* the notification: a module
	// function returning *dagger.File is lazy, so nothing is sent until
	// something reads the file. Skipping the merge to save an aggregation pass
	// — when delivery succeeded, say — would silently stop sending cards.
	//
	// The comment is rendered after, so it can carry the delivery record. The
	// card cannot: it was built before the POST it would have to report on.
	//
	// A notification that could not be delivered still does not fail the run:
	// the verdict is in the audit directory either way, and turning a webhook
	// outage into a red run would teach a team to stop passing the webhook. It
	// is a warned pass in the evidence instead of a line on stderr.
	if opts.teamsWebhook != nil {
		notifyEvidence := dag.Notify().Teams(
			opts.teamsWebhook,
			auditDir.File("combined-evidence.json"),
			pipeline,
			dagger.NotifyTeamsOpts{RunURL: opts.runUrl},
		)
		withDelivery := make([]*dagger.File, 0, len(evidenceFiles)+1)
		withDelivery = append(withDelivery, evidenceFiles...)
		withDelivery = append(withDelivery, notifyEvidence)
		auditDir = dag.Evidence().Wrap(
			withDelivery,
			opts.commitSha, opts.branch, opts.repoUrl,
		)
	}

	commentFile := dag.Notify().GithubBuildComment(
		auditDir.File("combined-evidence.json"),
		pipeline,
		dagger.NotifyGithubBuildCommentOpts{RunURL: opts.runUrl},
	)
	return auditDir.WithFile("comment.md", commentFile)
}
