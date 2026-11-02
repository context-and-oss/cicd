package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const stubTemplate = `<html><body><script type="application/json" id="ev">__EVIDENCE_JSON__</script><script>run()</script></body></html>`

// embeddedJSON pulls the document back out of a rendered page the way the
// browser does: the element's text is everything up to the first `</script`
// after the opening tag, in any letter case.
func embeddedJSON(t *testing.T, page string) string {
	t.Helper()
	const open = `id="ev">`
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("rendered page has no evidence element:\n%s", page)
	}
	body := page[start+len(open):]
	end := strings.Index(strings.ToLower(body), "</script")
	if end < 0 {
		t.Fatalf("evidence element never closes:\n%s", page)
	}
	return body[:end]
}

func TestRenderPage_placesTheDocumentInTheEvidenceElement(t *testing.T) {
	page, err := renderPage(stubTemplate, `{"passed":true,"findingsCount":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := embeddedJSON(t, page); got != `{"passed":true,"findingsCount":2}` {
		t.Errorf("embedded document = %s", got)
	}
	if strings.Contains(page, evidenceMarker) {
		t.Error("marker survived rendering")
	}
}

func TestRenderPage_aClosingTagInAnyCaseCannotEndTheElement(t *testing.T) {
	cases := map[string]string{
		"lowercase":        `{"errors":["found </script><img src=x onerror=alert(1)>"]}`,
		"uppercase":        `{"errors":["found </SCRIPT><img src=x onerror=alert(1)>"]}`,
		"mixed case":       `{"errors":["found </ScRiPt ><img>"]}`,
		"split by escape":  `{"warnings":["a <\/script> that was already escaped"]}`,
		"several":          `{"a":"</script>","b":["</script>","</SCRIPT>"]}`,
		"in a branch name": `{"repo":{"branch":"feat/</script>"}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			page, err := renderPage(stubTemplate, doc)
			if err != nil {
				t.Fatal(err)
			}
			got := embeddedJSON(t, page)
			var want, have any
			if err := json.Unmarshal([]byte(doc), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(got), &have); err != nil {
				t.Fatalf("embedded document is no longer JSON: %v\n%s", err, got)
			}
			wantB, _ := json.Marshal(want)
			haveB, _ := json.Marshal(have)
			if string(wantB) != string(haveB) {
				t.Errorf("round trip changed the document:\nwant %s\nhave %s", wantB, haveB)
			}
			// The element the page's own JavaScript lives in must still be the
			// second script, with the evidence intact before it.
			if !strings.HasSuffix(page, `</script><script>run()</script></body></html>`) {
				t.Errorf("page tail was rewritten:\n%s", page)
			}
		})
	}
}

func TestRenderPage_refusesADocumentThatIsNotJSON(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":     ``,
		"prose":     `semgrep: did not run`,
		"truncated": `{"passed":true`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderPage(stubTemplate, doc); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
				t.Errorf("err = %v, want a not-valid-JSON refusal", err)
			}
		})
	}
}

func TestRenderPage_refusesATemplateWithoutExactlyOneMarker(t *testing.T) {
	for name, tmpl := range map[string]string{
		"none":  `<html><script id="ev"></script></html>`,
		"twice": `<a>__EVIDENCE_JSON__</a><b>__EVIDENCE_JSON__</b>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderPage(tmpl, `{}`); err == nil || !strings.Contains(err.Error(), "want exactly one") {
				t.Errorf("err = %v, want a marker-count refusal", err)
			}
		})
	}
}

func TestEmbeddedTemplate_holdsTheMarkerOnceInsideTheEvidenceElement(t *testing.T) {
	if n := strings.Count(htmlTemplate, evidenceMarker); n != 1 {
		t.Fatalf("template.html holds the marker %d times, want 1", n)
	}
	if !strings.Contains(htmlTemplate, `id="ev">`+evidenceMarker+`</script>`) {
		t.Error("template.html's marker is not the sole content of the id=\"ev\" script element")
	}
	page, err := renderPage(htmlTemplate, `{"passed":false,"errors":["</script>"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := embeddedJSON(t, page); got != `{"passed":false,"errors":["<\/script>"]}` {
		t.Errorf("embedded document = %s", got)
	}
}
