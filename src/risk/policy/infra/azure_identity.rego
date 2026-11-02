package risk.azure

import rego.v1

# ── Managed Identity ─────────────────────────────────────────────────────────

has_managed_identity(res) if {
	contains(lower(res.identity.type), "systemassigned")
}

has_managed_identity(res) if {
	contains(lower(res.identity.type), "userassigned")
}

# AZURE-011: App Service / Function App without managed identity
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.web/sites"
	not has_managed_identity(res)
	finding := {
		"msg": sprintf("AZURE-011: App Service %q has no managed identity — use identity-based access instead of connection strings", [res.name]),
		"id": "AZURE-011",
		"title": "App Service missing managed identity",
		"severity": "medium",
		"category": "identity",
		"resource": res.name,
		"remediation": "Set identity.type: 'SystemAssigned' and replace connection-string access with managed-identity role assignments",
	}
}

# ── Storage Key Access ────────────────────────────────────────────────────────

# AZURE-012: Storage Account allows shared-key (non-identity) access
# Fires when allowSharedKeyAccess is absent (default true) or explicitly true.
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.storage/storageaccounts"
	not res.properties.allowSharedKeyAccess == false
	finding := {
		"msg": sprintf("AZURE-012: Storage account %q allows shared key access — prefer managed-identity or SAS with delegation", [res.name]),
		"id": "AZURE-012",
		"title": "Storage Account allows shared key access",
		"severity": "medium",
		"category": "identity",
		"resource": res.name,
		"remediation": "Set properties.allowSharedKeyAccess: false and use managed-identity or user-delegation SAS",
	}
}

# ── SQL Server Authentication ─────────────────────────────────────────────────

# AZURE-013: SQL Server does not enforce Azure AD-only authentication
# Fires when azureADOnlyAuthentication is absent (default false) or explicitly false.
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.sql/servers"
	not res.properties.administrators.azureADOnlyAuthentication == true
	finding := {
		"msg": sprintf("AZURE-013: SQL server %q does not enforce Azure AD-only authentication", [res.name]),
		"id": "AZURE-013",
		"title": "SQL Server allows local (SQL) authentication",
		"severity": "high",
		"category": "identity",
		"resource": res.name,
		"remediation": "Set properties.administrators.azureADOnlyAuthentication: true to disable SQL logins",
	}
}

# ── Key Vault Authorization ───────────────────────────────────────────────────

# AZURE-014: Key Vault not using RBAC authorization model
# Fires when enableRbacAuthorization is absent (default false) or explicitly false.
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.keyvault/vaults"
	not res.properties.enableRbacAuthorization == true
	finding := {
		"msg": sprintf("AZURE-014: Key Vault %q uses access-policy model instead of RBAC", [res.name]),
		"id": "AZURE-014",
		"title": "Key Vault using legacy access-policy authorization",
		"severity": "medium",
		"category": "identity",
		"resource": res.name,
		"remediation": "Set properties.enableRbacAuthorization: true and assign Key Vault roles via Azure RBAC",
	}
}

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
