package risk.pipeline_test

import rego.v1

import data.risk.pipeline

# ── helpers ───────────────────────────────────────────────────────────────────

gha_workflow(jobs) := {
	"on": {"push": {"branches": ["main"]}},
	"permissions": "read-all",
	"jobs": jobs,
}

simple_job(steps) := {"runs-on": "ubuntu-latest", "steps": steps}

# ── PIPE-001 ──────────────────────────────────────────────────────────────────

test_no_permissions_fires if {
	findings := pipeline.violation with input as {
		"on": {"push": {}},
		"jobs": {"build": simple_job([{"run": "echo hi"}])},
	}
	some f in findings
	f.id == "PIPE-001"
}

test_permissions_present_passes if {
	findings := pipeline.violation with input as gha_workflow({"build": simple_job([{"run": "echo hi"}])})
	count([f | f := findings[_]; f.id == "PIPE-001"]) == 0
}

# ── PIPE-002 ──────────────────────────────────────────────────────────────────

test_prt_object_trigger_fires if {
	findings := pipeline.violation with input as {
		"on": {"pull_request_target": {"types": ["opened"]}},
		"permissions": "read-all",
		"jobs": {"build": simple_job([])},
	}
	some f in findings
	f.id == "PIPE-002"
}

test_prt_array_trigger_fires if {
	findings := pipeline.violation with input as {
		"on": ["push", "pull_request_target"],
		"permissions": "read-all",
		"jobs": {"build": simple_job([])},
	}
	some f in findings
	f.id == "PIPE-002"
}

test_prt_string_trigger_fires if {
	findings := pipeline.violation with input as {
		"on": "pull_request_target",
		"permissions": "read-all",
		"jobs": {"build": simple_job([])},
	}
	some f in findings
	f.id == "PIPE-002"
}

test_pr_trigger_no_prt_passes if {
	findings := pipeline.violation with input as {
		"on": {"pull_request": {}, "push": {}},
		"permissions": "read-all",
		"jobs": {"build": simple_job([])},
	}
	count([f | f := findings[_]; f.id == "PIPE-002"]) == 0
}

# ── PIPE-003 ──────────────────────────────────────────────────────────────────

test_unpinned_action_fires if {
	findings := pipeline.violation with input as gha_workflow({"build": simple_job([
		{"uses": "actions/checkout@v4"},
	])})
	some f in findings
	f.id == "PIPE-003"
}

test_sha_pinned_action_passes if {
	findings := pipeline.violation with input as gha_workflow({"build": simple_job([
		{"uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"},
	])})
	count([f | f := findings[_]; f.id == "PIPE-003"]) == 0
}

test_local_action_not_flagged if {
	findings := pipeline.violation with input as gha_workflow({"build": simple_job([
		{"uses": "./.github/actions/my-action"},
	])})
	count([f | f := findings[_]; f.id == "PIPE-003"]) == 0
}

test_run_step_not_flagged if {
	findings := pipeline.violation with input as gha_workflow({"build": simple_job([
		{"run": "echo hello"},
	])})
	count([f | f := findings[_]; f.id == "PIPE-003"]) == 0
}

# ── PIPE-101 ──────────────────────────────────────────────────────────────────

test_azdo_no_trigger_fires if {
	findings := pipeline.violation with input as {
		"stages": [{"stage": "Build", "jobs": [{"job": "BuildApp", "steps": []}]}],
	}
	some f in findings
	f.id == "PIPE-101"
}

test_azdo_trigger_present_passes if {
	findings := pipeline.violation with input as {
		"trigger": ["main"],
		"stages": [{"stage": "Build", "jobs": [{"job": "BuildApp", "steps": []}]}],
	}
	count([f | f := findings[_]; f.id == "PIPE-101"]) == 0
}

test_azdo_trigger_none_passes if {
	findings := pipeline.violation with input as {
		"trigger": "none",
		"stages": [{"stage": "Build", "jobs": [{"job": "BuildApp", "steps": []}]}],
	}
	count([f | f := findings[_]; f.id == "PIPE-101"]) == 0
}

# ── PIPE-102 ──────────────────────────────────────────────────────────────────

test_azdo_deployment_no_environment_fires if {
	findings := pipeline.violation with input as {
		"trigger": ["main"],
		"stages": [{
			"stage": "Deploy",
			"jobs": [{"deployment": "DeployWeb", "strategy": {"runOnce": {}}}],
		}],
	}
	some f in findings
	f.id == "PIPE-102"
}

test_azdo_deployment_with_environment_passes if {
	findings := pipeline.violation with input as {
		"trigger": ["main"],
		"stages": [{
			"stage": "Deploy",
			"jobs": [{"deployment": "DeployWeb", "environment": "production", "strategy": {"runOnce": {}}}],
		}],
	}
	count([f | f := findings[_]; f.id == "PIPE-102"]) == 0
}

test_azdo_regular_job_not_flagged if {
	findings := pipeline.violation with input as {
		"trigger": ["main"],
		"stages": [{
			"stage": "Build",
			"jobs": [{"job": "BuildApp", "steps": []}],
		}],
	}
	count([f | f := findings[_]; f.id == "PIPE-102"]) == 0
}

# ── cross-type guard ──────────────────────────────────────────────────────────

test_non_pipeline_yaml_ignored if {
	findings := pipeline.violation with input as {"name": "my-app", "version": "1.0.0"}
	count(findings) == 0
}
