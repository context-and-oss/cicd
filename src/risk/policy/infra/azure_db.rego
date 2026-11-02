package risk.azure

import rego.v1

# ── PostgreSQL ────────────────────────────────────────────────────────────────

# AZURE-015: PostgreSQL Flexible Server public network access enabled
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.dbforpostgresql/flexibleservers"
	res.properties.network.publicNetworkAccess == "Enabled"
	finding := {
		"msg": sprintf("AZURE-015: PostgreSQL server %q has public network access enabled", [res.name]),
		"id": "AZURE-015",
		"title": "PostgreSQL Flexible Server exposed to public network",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.network.publicNetworkAccess: 'Disabled' and connect via private endpoint or VNet integration",
	}
}

# ── MySQL ─────────────────────────────────────────────────────────────────────

# AZURE-016: MySQL Flexible Server public network access enabled
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.dbformysql/flexibleservers"
	res.properties.network.publicNetworkAccess == "Enabled"
	finding := {
		"msg": sprintf("AZURE-016: MySQL server %q has public network access enabled", [res.name]),
		"id": "AZURE-016",
		"title": "MySQL Flexible Server exposed to public network",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.network.publicNetworkAccess: 'Disabled' and connect via private endpoint or VNet integration",
	}
}

# ── Cosmos DB ─────────────────────────────────────────────────────────────────

# AZURE-017: Cosmos DB account public network access enabled
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.documentdb/databaseaccounts"
	res.properties.publicNetworkAccess == "Enabled"
	finding := {
		"msg": sprintf("AZURE-017: Cosmos DB account %q has public network access enabled", [res.name]),
		"id": "AZURE-017",
		"title": "Cosmos DB account exposed to public network",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.publicNetworkAccess: 'Disabled' and use private endpoints",
	}
}

# ── Redis Cache ───────────────────────────────────────────────────────────────

# AZURE-018: Redis Cache non-SSL port enabled
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.cache/redis"
	res.properties.enableNonSslPort == true
	finding := {
		"msg": sprintf("AZURE-018: Redis Cache %q has non-SSL (port 6379) enabled", [res.name]),
		"id": "AZURE-018",
		"title": "Redis Cache non-SSL port enabled",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.enableNonSslPort: false and use SSL port 6380 only",
	}
}

# AZURE-019: Redis Cache minimum TLS below 1.2
# Fires when minimumTlsVersion is absent (default '1.0') or below '1.2'.
violation contains finding if {
	arm_template
	some res in input.resources
	lower(res.type) == "microsoft.cache/redis"
	not res.properties.minimumTlsVersion == "1.2"
	finding := {
		"msg": sprintf("AZURE-019: Redis Cache %q minimum TLS is below 1.2", [res.name]),
		"id": "AZURE-019",
		"title": "Redis Cache minimum TLS below 1.2",
		"severity": "high",
		"category": "data",
		"resource": res.name,
		"remediation": "Set properties.minimumTlsVersion: '1.2'",
	}
}

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
