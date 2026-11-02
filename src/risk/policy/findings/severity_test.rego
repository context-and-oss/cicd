package risk.severity_test

import rego.v1

import data.risk.severity

# high severity with accepted_risk → deny
test_deny_high_accepted_risk if {
	severity.deny["High/critical finding must be approved: abc — High risk"] with input as {
		"findings": [{"id": "abc", "title": "High risk", "severity": "high"}],
		"decisions": {"abc": {"status": "accepted_risk"}},
	}
}

# critical severity with accepted_risk → deny
test_deny_critical_accepted_risk if {
	severity.deny["High/critical finding must be approved: def — Critical"] with input as {
		"findings": [{"id": "def", "title": "Critical", "severity": "critical"}],
		"decisions": {"def": {"status": "accepted_risk"}},
	}
}

# high severity with approved → no deny from severity.rego
test_allow_high_approved if {
	count(severity.deny) == 0 with input as {
		"findings": [{"id": "abc", "title": "High risk", "severity": "high"}],
		"decisions": {"abc": {"status": "approved"}},
	}
}

# low severity with accepted_risk → no deny from severity.rego
test_allow_low_accepted_risk if {
	count(severity.deny) == 0 with input as {
		"findings": [{"id": "abc", "title": "Low risk", "severity": "low"}],
		"decisions": {"abc": {"status": "accepted_risk"}},
	}
}
