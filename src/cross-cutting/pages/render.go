// How the evidence document is put inside the page.
//
// Untagged (no //go:build !unit_test): main.go carries the Dagger build tag
// because the generated SDK panics outside a session, so the one decision
// this module makes — what in the evidence can break out of the script tag —
// lived where no test could reach it.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed template.html
var htmlTemplate string

// evidenceMarker is the placeholder template.html holds exactly once, inside
// its <script type="application/json" id="ev"> element.
const evidenceMarker = "__EVIDENCE_JSON__"

// renderPage places the evidence JSON into the template at evidenceMarker.
//
// The document sits in script data, where the HTML tokenizer ends the element
// at the first `</script` it meets — case-insensitively, and whatever JSON
// string it is inside. Every `</` in the document is therefore written as
// `<\/`, which JSON reads back as the same two characters (`\/` is an escaped
// solidus) and the tokenizer never reads as a tag opener. The earlier,
// narrower rule replaced the lowercase `</script>` only, so `</SCRIPT>` in a
// finding's text closed the element and the rest of the evidence rendered as
// the page.
//
// Refuses a document that is not JSON, because the page's own JSON.parse
// would refuse it in the reader's browser, after the site had been built and
// deployed as if it carried evidence. Refuses a template holding the marker
// other than exactly once: zero would build a page with no evidence at all,
// and two would put the same document where only the first was meant.
func renderPage(template, evidenceJSON string) (string, error) {
	if !json.Valid([]byte(evidenceJSON)) {
		return "", fmt.Errorf("evidence is not valid JSON; refusing to build a page that would render nothing")
	}
	if n := strings.Count(template, evidenceMarker); n != 1 {
		return "", fmt.Errorf("template holds %d occurrences of %s, want exactly one", n, evidenceMarker)
	}
	safe := strings.ReplaceAll(evidenceJSON, "</", `<\/`)
	return strings.Replace(template, evidenceMarker, safe, 1), nil
}
