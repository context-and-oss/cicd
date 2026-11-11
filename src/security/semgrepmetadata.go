package main

import _ "embed"

const semgrepMetadataPath = "/" + semgrepCicdRuleDir + "/semgrep_metadata.py"

//go:embed semgrep_metadata.py
var semgrepMetadataScript string
