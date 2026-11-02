package risk.pipeline

import rego.v1

# ── Guards ────────────────────────────────────────────────────────────────────

# GitHub Actions workflows have `jobs` as an object (keyed by job name).
github_actions if {
	is_object(input.jobs)
}

# Azure DevOps multi-stage pipelines have `stages` as an array.
# GitHub Actions does not use a `stages` key, so this guard is exclusive.
azdo_pipeline if {
	is_array(input.stages)
}

# ── GitHub Actions ────────────────────────────────────────────────────────────

# PIPE-001: No top-level permissions block — workflow runs with default write permissions.
violation contains finding if {
	github_actions
	not input.permissions
	finding := {
		"msg": "PIPE-001: GitHub Actions workflow has no top-level permissions block — runs with GITHUB_TOKEN write access to all scopes",
		"id": "PIPE-001",
		"title": "GitHub Actions workflow missing permissions block",
		"severity": "medium",
		"category": "ops",
		"resource": "workflow",
		"remediation": "Add 'permissions: read-all' at the workflow level and grant write access only to the scopes that need it",
	}
}

# PIPE-002: pull_request_target trigger — untrusted fork code can access secrets.
prt_in_on_object if {
	is_object(input["on"])
	some k, _ in input["on"]
	k == "pull_request_target"
}

prt_in_on_array if {
	is_array(input["on"])
	some evt in input["on"]
	evt == "pull_request_target"
}

prt_trigger if { prt_in_on_object }

prt_trigger if { prt_in_on_array }

prt_trigger if { input["on"] == "pull_request_target" }

violation contains finding if {
	github_actions
	prt_trigger
	finding := {
		"msg": "PIPE-002: GitHub Actions workflow uses pull_request_target — fork code executes with write token and access to secrets",
		"id": "PIPE-002",
		"title": "GitHub Actions uses pull_request_target trigger",
		"severity": "high",
		"category": "ops",
		"resource": "workflow",
		"remediation": "Replace with pull_request trigger, or checkout untrusted code in a separate job with read-only permissions and no secret access",
	}
}

# PIPE-003: Action not pinned to a full commit SHA — supply chain risk.
# GitHub Actions SHA pinning uses a 40-char hex commit hash, e.g. actions/checkout@11bd71...
sha_pinned(uses) if {
	regex.match(`^[^@]+@[0-9a-f]{40}$`, uses)
}

violation contains finding if {
	github_actions
	some _, job in input.jobs
	is_array(job.steps)
	some step in job.steps
	is_string(step.uses)
	not startswith(step.uses, "./")
	not sha_pinned(step.uses)
	finding := {
		"msg": sprintf("PIPE-003: Action %q is not pinned to a commit SHA", [step.uses]),
		"id": "PIPE-003",
		"title": "GitHub Actions action not SHA-pinned",
		"severity": "medium",
		"category": "ops",
		"resource": step.uses,
		"remediation": "Pin to a full commit SHA (e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683) and use Dependabot to keep it current",
	}
}

# ── Azure DevOps ──────────────────────────────────────────────────────────────

# PIPE-101: No trigger configuration — pipeline fires on every push to every branch.
violation contains finding if {
	azdo_pipeline
	not input.trigger
	finding := {
		"msg": "PIPE-101: Azure DevOps pipeline has no trigger configuration — fires on every commit to every branch by default",
		"id": "PIPE-101",
		"title": "Azure DevOps pipeline missing trigger configuration",
		"severity": "medium",
		"category": "ops",
		"resource": "pipeline",
		"remediation": "Add a trigger block that restricts CI runs to specific branches (e.g. trigger: [main, release/*])",
	}
}

# PIPE-102: Deployment job without a named environment — bypasses approval gates.
violation contains finding if {
	azdo_pipeline
	some stage in input.stages
	some job in stage.jobs
	is_string(job.deployment)
	not "environment" in object.keys(job)
	finding := {
		"msg": sprintf("PIPE-102: Deployment job %q in stage %q has no environment — approval gates cannot be enforced", [job.deployment, stage.stage]),
		"id": "PIPE-102",
		"title": "Azure DevOps deployment job missing environment",
		"severity": "high",
		"category": "ops",
		"resource": job.deployment,
		"remediation": "Add 'environment: <name>' to the deployment job; configure approval checks on that environment in the Azure DevOps portal",
	}
}

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
