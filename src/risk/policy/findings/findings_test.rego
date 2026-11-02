package risk.findings_test

import rego.v1

import data.risk.findings

# finding with no decision entry → deny
test_deny_when_no_decision if {
	findings.deny["Finding not reviewed: abc — Missing decision"] with input as {
		"findings": [{"id": "abc", "title": "Missing decision", "severity": "low"}],
		"decisions": {},
	}
}

# finding with needs_review status → deny
test_deny_when_needs_review if {
	findings.deny["Finding still needs review: abc — Unreviewed"] with input as {
		"findings": [{"id": "abc", "title": "Unreviewed", "severity": "low"}],
		"decisions": {"abc": {"status": "needs_review"}},
	}
}

# finding with approved status → no deny
test_allow_when_approved if {
	count(findings.deny) == 0 with input as {
		"findings": [{"id": "abc", "title": "Reviewed", "severity": "low"}],
		"decisions": {"abc": {"status": "approved"}},
	}
}

# finding with accepted_risk status → no deny from findings.rego
test_allow_accepted_risk if {
	count(findings.deny) == 0 with input as {
		"findings": [{"id": "abc", "title": "Accepted", "severity": "low"}],
		"decisions": {"abc": {"status": "accepted_risk"}},
	}
}

# high-severity needs_review must NOT fire from findings.rego (severity.rego owns it).
# This confirms the double-fire exclusion clause works correctly.
test_high_needs_review_not_fired_from_findings if {
	count(findings.deny) == 0 with input as {
		"findings": [{"id": "abc", "title": "High", "severity": "high"}],
		"decisions": {"abc": {"status": "needs_review"}},
	}
}
