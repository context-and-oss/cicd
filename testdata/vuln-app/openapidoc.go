package main

import _ "embed"

// openapiDoc is the checked-in document, embedded rather than duplicated: the
// api scan can be driven either from this file (--api-spec) or from the path it
// is served on (--api-spec-path /openapi.json), and the two must describe the
// same surface or the fixture proves nothing about the second route.
//
//go:embed openapi.json
var openapiDoc string
