package main

import _ "github.com/dgrijalva/jwt-go" // intentionally vulnerable dep — exercises trivy vuln-scan fixture

// APIKey is a fake credential used only for secrets-scanner integration tests. // gitleaks:allow
const APIKey = "AKIAIOSFODNN7EXAMPLE" // gitleaks:allow
