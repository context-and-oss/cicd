package risk.azure_test

import rego.v1

import data.risk.azure

arm_tags(resources) := {
	"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	"contentVersion": "1.0.0.0",
	"resources": resources,
}

tagged(extra) := object.union(
	{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
		"tags": {
			"environment": "prod",
			"owner": "platform",
			"project": "my-project",
		},
	},
	extra,
)

# ── TAG-001 ───────────────────────────────────────────────────────────────────

test_missing_environment_tag_fires if {
	findings := azure.violation with input as arm_tags([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
		"tags": {"owner": "platform", "project": "my-project"},
	}])
	some f in findings
	f.id == "TAG-001"
}

# ── TAG-002 ───────────────────────────────────────────────────────────────────

test_missing_owner_tag_fires if {
	findings := azure.violation with input as arm_tags([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
		"tags": {"environment": "prod", "project": "my-project"},
	}])
	some f in findings
	f.id == "TAG-002"
}

# ── TAG-003 ───────────────────────────────────────────────────────────────────

test_missing_project_tag_fires if {
	findings := azure.violation with input as arm_tags([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
		"tags": {"environment": "prod", "owner": "platform"},
	}])
	some f in findings
	f.id == "TAG-003"
}

test_all_required_tags_present_passes if {
	findings := azure.violation with input as arm_tags([tagged({})])
	tag_findings := [f | f := findings[_]; startswith(f.id, "TAG-")]
	count(tag_findings) == 0
}

test_no_tags_block_fires_all_three if {
	findings := azure.violation with input as arm_tags([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
	}])
	tag_findings := {f.id | f := findings[_]; startswith(f.id, "TAG-")}
	tag_findings == {"TAG-001", "TAG-002", "TAG-003"}
}

test_sub_resource_not_checked_for_tags if {
	findings := azure.violation with input as arm_tags([{
		"type": "Microsoft.Storage/storageAccounts/blobServices",
		"name": "mystorage/default",
		"properties": {},
	}])
	tag_findings := [f | f := findings[_]; startswith(f.id, "TAG-")]
	count(tag_findings) == 0
}
