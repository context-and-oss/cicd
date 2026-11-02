package risk.azure_test

import rego.v1

import data.risk.azure

arm(resources) := {
	"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	"contentVersion": "1.0.0.0",
	"resources": resources,
}

# ── helper ────────────────────────────────────────────────────────────────────

test_non_arm_json_ignored if {
	findings := azure.violation with input as {"name": "package.json", "version": "1.0.0"}
	count(findings) == 0
}

# ── AZURE-001 ─────────────────────────────────────────────────────────────────

test_storage_public_blob_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowBlobPublicAccess": true},
	}])
	some f in findings
	f.id == "AZURE-001"
}

test_storage_public_blob_false_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"allowBlobPublicAccess": false},
	}])
	count([f | f := findings[_]; f.id == "AZURE-001"]) == 0
}

# ── AZURE-002 ─────────────────────────────────────────────────────────────────

test_storage_http_allowed_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"supportsHttpsTrafficOnly": false},
	}])
	some f in findings
	f.id == "AZURE-002"
}

# ── AZURE-003 ─────────────────────────────────────────────────────────────────

test_storage_tls10_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"minimumTlsVersion": "TLS1_0"},
	}])
	some f in findings
	f.id == "AZURE-003"
}

test_storage_tls12_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {"minimumTlsVersion": "TLS1_2"},
	}])
	count([f | f := findings[_]; f.id == "AZURE-003"]) == 0
}

test_storage_tls_absent_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Storage/storageAccounts",
		"name": "mystorage",
		"properties": {},
	}])
	some f in findings
	f.id == "AZURE-003"
}

# ── AZURE-004 ─────────────────────────────────────────────────────────────────

test_sql_public_access_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Sql/servers",
		"name": "mysql",
		"properties": {"publicNetworkAccess": "Enabled"},
	}])
	some f in findings
	f.id == "AZURE-004"
}

# ── AZURE-005 ─────────────────────────────────────────────────────────────────

test_keyvault_public_network_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.KeyVault/vaults",
		"name": "myvault",
		"properties": {"networkAcls": {"defaultAction": "Allow"}},
	}])
	some f in findings
	f.id == "AZURE-005"
}

# ── AZURE-006 ─────────────────────────────────────────────────────────────────

test_keyvault_soft_delete_disabled_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.KeyVault/vaults",
		"name": "myvault",
		"properties": {"enableSoftDelete": false},
	}])
	some f in findings
	f.id == "AZURE-006"
}

# ── AZURE-007 ─────────────────────────────────────────────────────────────────

test_acr_admin_enabled_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.ContainerRegistry/registries",
		"name": "myregistry",
		"properties": {"adminUserEnabled": true},
	}])
	some f in findings
	f.id == "AZURE-007"
}

test_acr_admin_disabled_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.ContainerRegistry/registries",
		"name": "myregistry",
		"properties": {"adminUserEnabled": false},
	}])
	count([f | f := findings[_]; f.id == "AZURE-007"]) == 0
}

# ── AZURE-008 ─────────────────────────────────────────────────────────────────

test_acr_public_network_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.ContainerRegistry/registries",
		"name": "myregistry",
		"properties": {"publicNetworkAccess": "Enabled"},
	}])
	some f in findings
	f.id == "AZURE-008"
}

test_acr_public_network_disabled_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.ContainerRegistry/registries",
		"name": "myregistry",
		"properties": {"publicNetworkAccess": "Disabled"},
	}])
	count([f | f := findings[_]; f.id == "AZURE-008"]) == 0
}

# ── AZURE-009 ─────────────────────────────────────────────────────────────────

test_app_service_http_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"httpsOnly": false},
	}])
	some f in findings
	f.id == "AZURE-009"
}

test_app_service_https_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"httpsOnly": true},
	}])
	count([f | f := findings[_]; f.id == "AZURE-009"]) == 0
}

# ── AZURE-010 ─────────────────────────────────────────────────────────────────

test_app_service_tls10_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"siteConfig": {"minTlsVersion": "1.0"}},
	}])
	some f in findings
	f.id == "AZURE-010"
}

test_app_service_tls12_passes if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"siteConfig": {"minTlsVersion": "1.2"}},
	}])
	count([f | f := findings[_]; f.id == "AZURE-010"]) == 0
}

test_app_service_tls_absent_fires if {
	findings := azure.violation with input as arm([{
		"type": "Microsoft.Web/sites",
		"name": "myapp",
		"properties": {"siteConfig": {}},
	}])
	some f in findings
	f.id == "AZURE-010"
}
