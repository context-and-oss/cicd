package risk.findings

import rego.v1

deny contains msg if {
	finding := input.findings[_]
	not input.decisions[finding.id]
	msg := sprintf("Finding not reviewed: %s — %s", [finding.id, finding.title])
}

# severity.rego handles critical/high findings; this rule covers medium/low only.
# A critical/high finding on needs_review fires severity.rego ("must be approved"),
# not this rule, to avoid double-counting the same finding.
deny contains msg if {
	finding := input.findings[_]
	decision := input.decisions[finding.id]
	decision.status == "needs_review"
	not finding.severity in {"critical", "high"}
	msg := sprintf("Finding still needs review: %s — %s", [finding.id, finding.title])
}
