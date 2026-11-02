package risk.azure_test

import rego.v1

import data.risk.azure

arm_db(resources) := {
	"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
	"contentVersion": "1.0.0.0",
	"resources": resources,
}

# ── AZURE-015 ─────────────────────────────────────────────────────────────────

test_postgres_public_access_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.DBforPostgreSQL/flexibleServers",
		"name": "mypg",
		"properties": {"network": {"publicNetworkAccess": "Enabled"}},
	}])
	some f in findings
	f.id == "AZURE-015"
}

test_postgres_public_access_disabled_passes if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.DBforPostgreSQL/flexibleServers",
		"name": "mypg",
		"properties": {"network": {"publicNetworkAccess": "Disabled"}},
	}])
	count([f | f := findings[_]; f.id == "AZURE-015"]) == 0
}

# ── AZURE-016 ─────────────────────────────────────────────────────────────────

test_mysql_public_access_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.DBforMySQL/flexibleServers",
		"name": "mymysql",
		"properties": {"network": {"publicNetworkAccess": "Enabled"}},
	}])
	some f in findings
	f.id == "AZURE-016"
}

# ── AZURE-017 ─────────────────────────────────────────────────────────────────

test_cosmosdb_public_access_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.DocumentDB/databaseAccounts",
		"name": "mycosmos",
		"properties": {"publicNetworkAccess": "Enabled"},
	}])
	some f in findings
	f.id == "AZURE-017"
}

test_cosmosdb_public_access_disabled_passes if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.DocumentDB/databaseAccounts",
		"name": "mycosmos",
		"properties": {"publicNetworkAccess": "Disabled"},
	}])
	count([f | f := findings[_]; f.id == "AZURE-017"]) == 0
}

# ── AZURE-018 ─────────────────────────────────────────────────────────────────

test_redis_non_ssl_enabled_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.Cache/Redis",
		"name": "myredis",
		"properties": {"enableNonSslPort": true},
	}])
	some f in findings
	f.id == "AZURE-018"
}

test_redis_non_ssl_disabled_passes if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.Cache/Redis",
		"name": "myredis",
		"properties": {"enableNonSslPort": false},
	}])
	count([f | f := findings[_]; f.id == "AZURE-018"]) == 0
}

# ── AZURE-019 ─────────────────────────────────────────────────────────────────

test_redis_tls_absent_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.Cache/Redis",
		"name": "myredis",
		"properties": {"enableNonSslPort": false},
	}])
	some f in findings
	f.id == "AZURE-019"
}

test_redis_tls10_fires if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.Cache/Redis",
		"name": "myredis",
		"properties": {"minimumTlsVersion": "1.0"},
	}])
	some f in findings
	f.id == "AZURE-019"
}

test_redis_tls12_passes if {
	findings := azure.violation with input as arm_db([{
		"type": "Microsoft.Cache/Redis",
		"name": "myredis",
		"properties": {"minimumTlsVersion": "1.2"},
	}])
	count([f | f := findings[_]; f.id == "AZURE-019"]) == 0
}
