package risk.azure_test

import rego.v1

import data.risk.azure

arm(resources) := {
	"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	"contentVersion": "1.0.0.0",
	"resources": resources,
}

# ── AZURE-011 ─────────────────────────────────────────────────────────────────

test_app_service_no_identity_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"httpsOnly": true},
	}])
	some f in findings
	f.id == "AZURE-011"
}

test_app_service_system_identity_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"identity": {"type": "SystemAssigned"},
		"properties": {"httpsOnly": true},
	}])
	count([f | f := findings[_]; f.id == "AZURE-011"]) == 0
}

test_app_service_user_identity_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"identity": {"type": "UserAssigned"},
		"properties": {"httpsOnly": true},
	}])
	count([f | f := findings[_]; f.id == "AZURE-011"]) == 0
}

# ── AZURE-012 ─────────────────────────────────────────────────────────────────

test_storage_key_access_absent_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {},
	}])
	some f in findings
	f.id == "AZURE-012"
}

test_storage_key_access_true_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": true},
	}])
	some f in findings
	f.id == "AZURE-012"
}

test_storage_key_access_false_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowSharedKeyAccess": false},
	}])
	count([f | f := findings[_]; f.id == "AZURE-012"]) == 0
}

# ── AZURE-013 ─────────────────────────────────────────────────────────────────

test_sql_ad_only_absent_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Sql/servers",
		"name": "mysql",
		"properties": {},
	}])
	some f in findings
	f.id == "AZURE-013"
}

test_sql_ad_only_false_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Sql/servers",
		"name": "mysql",
		"properties": {"administrators": {"azureADOnlyAuthentication": false}},
	}])
	some f in findings
	f.id == "AZURE-013"
}

test_sql_ad_only_true_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Sql/servers",
		"name": "mysql",
		"properties": {"administrators": {"azureADOnlyAuthentication": true}},
	}])
	count([f | f := findings[_]; f.id == "AZURE-013"]) == 0
}

# ── AZURE-014 ─────────────────────────────────────────────────────────────────

test_keyvault_no_rbac_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.KeyVault/vaults",
		"name": "myvault",
		"properties": {"enableSoftDelete": true},
	}])
	some f in findings
	f.id == "AZURE-014"
}

test_keyvault_rbac_enabled_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.KeyVault/vaults",
		"name": "myvault",
		"properties": {"enableRbacAuthorization": true},
	}])
	count([f | f := findings[_]; f.id == "AZURE-014"]) == 0
}
