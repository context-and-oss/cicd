package risk.severity

import rego.v1

deny contains msg if {
	finding := input.findings[_]
	finding.severity in {"critical", "high"}
	decision := input.decisions[finding.id]
	decision.status != "approved"
	msg := sprintf("High/critical finding must be approved: %s — %s", [finding.id, finding.title])
}
