# src/risk/policy/infra/azure.rego
#
# Policies run against compiled ARM JSON (az bicep build --file *.bicep --stdout > template.json).
# Conftest v0.58.0 does not support .bicep parsing natively.
package risk.azure

import rego.v1

# Only evaluate files that look like ARM deployment templates.
arm_template if {
	contains(input["$schema"], "schema.management.azure.com")
}

# ── Storage Accounts ─────────────────────────────────────────────────────────

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.storage/storageaccounts"
	res.properties.allowBlobPublicAccess == true
	finding := {
		"msg": sprintf("AZURE-001: Storage account %q allows public blob access", [res.name]),
		"id": "AZURE-001",
		"title": "Storage account allows public blob access",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.allowBlobPublicAccess: false",
	}
}

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.storage/storageaccounts"
	res.properties.supportsHttpsTrafficOnly == false
	finding := {
		"msg": sprintf("AZURE-002: Storage account %q allows unencrypted HTTP traffic", [res.name]),
		"id": "AZURE-002",
		"title": "Storage account allows HTTP traffic",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.supportsHttpsTrafficOnly: true",
	}
}

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.storage/storageaccounts"
	not res.properties.minimumTlsVersion == "TLS1_2"
	finding := {
		"msg": sprintf("AZURE-003: Storage account %q minimum TLS is below 1.2", [res.name]),
		"id": "AZURE-003",
		"title": "Storage account minimum TLS below 1.2",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.minimumTlsVersion: 'TLS1_2'",
	}
}

# ── SQL Servers ───────────────────────────────────────────────────────────────

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.sql/servers"
	res.properties.publicNetworkAccess == "Enabled"
	finding := {
		"msg": sprintf("AZURE-004: SQL server %q has public network access enabled", [res.name]),
		"id": "AZURE-004",
		"title": "SQL server exposed to public network",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.publicNetworkAccess: 'Disabled' and use private endpoints",
	}
}

# ── Key Vaults ────────────────────────────────────────────────────────────────

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.keyvault/vaults"
	res.properties.networkAcls.defaultAction == "Allow"
	finding := {
		"msg": sprintf("AZURE-005: Key Vault %q network ACL default action is Allow — publicly reachable", [res.name]),
		"id": "AZURE-005",
		"title": "Key Vault open to public network",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.networkAcls.defaultAction: 'Deny' and add required IP/vnet rules",
	}
}

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.keyvault/vaults"
	res.properties.enableSoftDelete == false
	finding := {
		"msg": sprintf("AZURE-006: Key Vault %q has soft delete disabled — secrets can be permanently lost", [res.name]),
		"id": "AZURE-006",
		"title": "Key Vault soft delete disabled",
		"severity": "high",
		"category": "ops",
		"resource": res.name,
		"remediation": "Set properties.enableSoftDelete: true and properties.enablePurgeProtection: true",
	}
}

# ── Container Registries ──────────────────────────────────────────────────────

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.containerregistry/registries"
	res.properties.adminUserEnabled == true
	finding := {
		"msg": sprintf("AZURE-007: Container Registry %q has admin user enabled", [res.name]),
		"id": "AZURE-007",
		"title": "Container Registry admin user enabled",
		"severity": "medium",
		"category": "ops",
		"resource": res.name,
		"remediation": "Set properties.adminUserEnabled: false; use managed identity or service principal",
	}
}

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.containerregistry/registries"
	res.properties.publicNetworkAccess == "Enabled"
	finding := {
		"msg": sprintf("AZURE-008: Container Registry %q has public network access enabled", [res.name]),
		"id": "AZURE-008",
		"title": "Container Registry exposed to public network",
		"severity": "medium",
		"category": "ops",
		"resource": res.name,
		"remediation": "Set properties.publicNetworkAccess: 'Disabled' and use private endpoints",
	}
}

# ── App Services ──────────────────────────────────────────────────────────────

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.web/sites"
	res.properties.httpsOnly == false
	finding := {
		"msg": sprintf("AZURE-009: App Service %q does not enforce HTTPS", [res.name]),
		"id": "AZURE-009",
		"title": "App Service allows HTTP traffic",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.httpsOnly: true",
	}
}

violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.web/sites"
	not res.properties.siteConfig.minTlsVersion == "1.2"
	finding := {
		"msg": sprintf("AZURE-010: App Service %q minimum TLS is below 1.2", [res.name]),
		"id": "AZURE-010",
		"title": "App Service minimum TLS below 1.2",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.siteConfig.minTlsVersion: '1.2'",
	}
}

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
