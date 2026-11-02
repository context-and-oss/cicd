package evidence_test

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/context-and-oss/cicd/internal/evidence"
)

// schema.json has drifted from schema.go three times (CAPS-033, CAPS-036,
// CAPS-037), and each time the response was to record the drift in a capsule
// rather than fix it — reasonably, because a document nothing reads is not
// worth hand-maintaining. It declares additionalProperties:false, so every
// drift left it rejecting envelopes that ship in production.
//
// These tests make the structure impossible to drift again. They deliberately
// do NOT validate a runtime envelope against the schema, and they assert
// nothing about the enums, ranges and formats in the file: those are
// hand-authored, carry information the Go tags cannot express, and are the
// reason schema.json is not simply generated. What is enforced is the part
// that actually broke — which properties exist, which are required, and what
// broad JSON type each carries.

// schemaPath is relative to this package directory, where `go test` runs.
const schemaPath = "schema.json"

type schemaDocument struct {
	Defs map[string]schemaDefinition `json:"$defs"`
}

type schemaDefinition struct {
	Type       string                    `json:"type"`
	Required   []string                  `json:"required"`
	Properties map[string]schemaProperty `json:"properties"`
}

type schemaProperty struct {
	Type                 string          `json:"type"`
	Const                string          `json:"const"`
	Ref                  string          `json:"$ref"`
	Items                *schemaProperty `json:"items"`
	AdditionalProperties *schemaProperty `json:"additionalProperties"`
}

// definitionFor pairs each $defs entry that describes a Go struct with that
// struct. Scalar definitions (severity) are referenced but have no struct of
// their own, so they are absent here on purpose;
// TestEveryStructReachableFromEnvelopeHasADefinition stops that absence from
// becoming a hiding place for a new struct field.
var definitionFor = map[string]reflect.Type{
	"evidence-envelope-v1": reflect.TypeOf(evidence.Envelope{}),
	"toolInfo":             reflect.TypeOf(evidence.ToolInfo{}),
	"repoContext":          reflect.TypeOf(evidence.RepoContext{}),
	"finding":              reflect.TypeOf(evidence.Finding{}),
	"testCounts":           reflect.TypeOf(evidence.TestCounts{}),
	"sourceStatus":         reflect.TypeOf(evidence.SourceStatus{}),
	"examined":             reflect.TypeOf(evidence.Examined{}),
	"ruleSet":              reflect.TypeOf(evidence.RuleSet{}),
	"concernRollup":        reflect.TypeOf(evidence.ConcernRollup{}),
	"concernReport":        reflect.TypeOf(evidence.ConcernReport{}),
}

var (
	rawMessageType = reflect.TypeOf(json.RawMessage(nil))
	timeType       = reflect.TypeOf(time.Time{})
)

func loadSchema(t *testing.T) schemaDocument {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	var doc schemaDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", schemaPath, err)
	}
	if len(doc.Defs) == 0 {
		t.Fatalf("%s declares no $defs", schemaPath)
	}
	return doc
}

type goField struct {
	name      string
	omitEmpty bool
	typ       reflect.Type
}

// goFieldsOf reports the JSON view of a struct: the wire name of every field
// that serialises, and whether it may be absent.
func goFieldsOf(t reflect.Type) []goField {
	var out []goField
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = f.Name
		}
		omit := false
		for _, opt := range parts[1:] {
			if opt == "omitempty" {
				omit = true
			}
		}
		out = append(out, goField{name: name, omitEmpty: omit, typ: f.Type})
	}
	return out
}

// jsonTypesFor gives the JSON Schema `type` values a Go type may legitimately
// be described as, or nil where no single answer is right and the schema is
// left free to choose.
func jsonTypesFor(t reflect.Type) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t {
	case rawMessageType:
		// An opaque embedded payload (SARIF, CycloneDX, a licence report).
		// Describing it as an object or leaving it unconstrained are both
		// honest, so no type is asserted.
		return nil
	case timeType:
		return []string{"string"}
	}
	switch t.Kind() {
	case reflect.String:
		return []string{"string"}
	case reflect.Bool:
		return []string{"boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []string{"integer"}
	case reflect.Float32, reflect.Float64:
		return []string{"number"}
	case reflect.Map, reflect.Struct:
		return []string{"object"}
	case reflect.Slice, reflect.Array:
		return []string{"array"}
	}
	return nil
}

func TestSchemaJSONPropertiesMatchStructTags(t *testing.T) {
	doc := loadSchema(t)

	for def, typ := range definitionFor {
		t.Run(def, func(t *testing.T) {
			d, ok := doc.Defs[def]
			if !ok {
				t.Fatalf("$defs has no %q, but %s is mapped to it", def, typ)
			}

			fields := goFieldsOf(typ)
			inGo := map[string]bool{}
			for _, f := range fields {
				inGo[f.name] = true
			}

			// additionalProperties:false is what makes an omission a
			// rejection rather than a shrug, so both directions matter.
			for _, f := range fields {
				if _, ok := d.Properties[f.name]; !ok {
					t.Errorf("%s.%s ships in every envelope but $defs/%s has no such property — additionalProperties:false makes the schema reject it",
						typ.Name(), f.name, def)
				}
			}
			for name := range d.Properties {
				if !inGo[name] {
					t.Errorf("$defs/%s declares property %q, which %s does not serialise", def, name, typ.Name())
				}
			}
		})
	}
}

func TestSchemaJSONRequiredMatchesOmitEmpty(t *testing.T) {
	doc := loadSchema(t)

	for def, typ := range definitionFor {
		t.Run(def, func(t *testing.T) {
			d := doc.Defs[def]

			// A field without omitempty always appears on the wire, so it is
			// required; a field with omitempty may be absent, so it is not.
			// The mapping is exact, which is why it can be asserted rather
			// than reviewed.
			var wantRequired []string
			for _, f := range goFieldsOf(typ) {
				if !f.omitEmpty {
					wantRequired = append(wantRequired, f.name)
				}
			}
			got := append([]string(nil), d.Required...)
			sort.Strings(got)
			sort.Strings(wantRequired)

			if !reflect.DeepEqual(got, wantRequired) {
				t.Errorf("$defs/%s required mismatch\n  schema.json: %v\n  schema.go:   %v", def, got, wantRequired)
			}
		})
	}
}

func TestSchemaJSONPropertyTypesMatchStructTags(t *testing.T) {
	doc := loadSchema(t)

	// A property whose $ref names a struct definition must name the right
	// one: without this, `tests` could point at $defs/finding and the key-set
	// tests above would still pass.
	refFor := map[reflect.Type]string{}
	for def, typ := range definitionFor {
		refFor[typ] = "#/$defs/" + def
	}

	elemStructRef := func(t reflect.Type) (string, bool) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			if t == rawMessageType {
				return "", false
			}
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || t == timeType {
			return "", false
		}
		ref, ok := refFor[t]
		return ref, ok
	}

	for def, typ := range definitionFor {
		t.Run(def, func(t *testing.T) {
			d := doc.Defs[def]
			for _, f := range goFieldsOf(typ) {
				prop, ok := d.Properties[f.name]
				if !ok {
					continue // reported by TestSchemaJSONPropertiesMatchStructTags
				}

				if want, isStruct := elemStructRef(f.typ); isStruct {
					// Where the struct sits decides where the $ref sits.
					var got string
					switch {
					case prop.Items != nil:
						got = prop.Items.Ref
					case prop.AdditionalProperties != nil:
						got = prop.AdditionalProperties.Ref
					default:
						got = prop.Ref
					}
					if got != want {
						t.Errorf("%s.%s carries %s, so its schema should reference %s, got %q",
							typ.Name(), f.name, f.typ, want, got)
					}
					continue
				}

				want := jsonTypesFor(f.typ)
				if want == nil || prop.Type == "" {
					// Either the Go type admits several honest encodings, or
					// the schema deliberately leaves the property open.
					continue
				}
				matched := false
				for _, w := range want {
					if prop.Type == w {
						matched = true
					}
				}
				if !matched {
					t.Errorf("%s.%s is %s, so its schema type should be one of %v, got %q",
						typ.Name(), f.name, f.typ, want, prop.Type)
				}
			}
		})
	}
}

func TestEveryStructReachableFromEnvelopeHasADefinition(t *testing.T) {
	// definitionFor is a hand-written table, so it can go stale in exactly
	// the way schema.json did: add a struct-typed field to Envelope, forget
	// the table, and every test above passes without ever looking at it.
	// This walks the envelope instead of trusting the table.
	seen := map[reflect.Type]bool{}
	var found []reflect.Type

	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
			typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			if typ == rawMessageType {
				return
			}
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == timeType || seen[typ] {
			return
		}
		seen[typ] = true
		found = append(found, typ)
		for _, f := range goFieldsOf(typ) {
			walk(f.typ)
		}
	}
	walk(reflect.TypeOf(evidence.Envelope{}))

	mapped := map[reflect.Type]bool{}
	for _, typ := range definitionFor {
		mapped[typ] = true
	}
	for _, typ := range found {
		if !mapped[typ] {
			t.Errorf("%s is reachable from Envelope but has no $defs entry in definitionFor — add the definition to schema.json and the mapping here", typ)
		}
	}
	for _, typ := range definitionFor {
		if !seen[typ] {
			t.Errorf("definitionFor maps %s, which is no longer reachable from Envelope — drop it from the table and from schema.json", typ)
		}
	}
}
