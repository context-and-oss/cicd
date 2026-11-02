package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// cdxDocument is the merged CycloneDX 1.5 document produced by mergeCycloneDX.
//
// Field order follows the spec's own ordering so the marshalled document reads
// the way the schema documents it: what this is, which BOM it is, what it
// describes, then the contents.
type cdxDocument struct {
	BOMFormat       string            `json:"bomFormat"`
	SpecVersion     string            `json:"specVersion"`
	SerialNumber    string            `json:"serialNumber,omitempty"`
	Version         int               `json:"version"`
	Metadata        *cdxMetadata      `json:"metadata,omitempty"`
	Components      []json.RawMessage `json:"components,omitempty"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities,omitempty"`
}

// mergeCycloneDX aggregates the CycloneDX components and vulnerabilities from
// every envelope into one identity-preserving document.
//
// Identity is resolved per record (see cdxIdentityKey): records sharing an
// identity are folded together field-by-field — complementary data merges
// losslessly (missing/empty fields fill in, arrays union with dedup), and a
// genuine conflict (two different non-empty scalar values for the same field)
// is returned as an error rather than silently choosing one side. Records
// with no safe identity are kept distinct unless byte-for-byte identical,
// since merging complementary data across records we cannot prove are the
// same thing would be unsafe.
func mergeCycloneDX(envs []*envelope, repo repoContext, now time.Time) (cdxDocument, error) {
	doc := cdxDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: cdxSerialNumber(repo),
		Version:      1,
		Metadata:     buildCDXMetadata(repo, now),
	}

	var rawComponents, rawVulns []json.RawMessage
	for _, e := range envs {
		if e.CycloneDXReport == nil {
			continue
		}
		var src struct {
			Components      []json.RawMessage `json:"components"`
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(e.CycloneDXReport, &src); err != nil {
			continue
		}
		rawComponents = append(rawComponents, src.Components...)
		rawVulns = append(rawVulns, src.Vulnerabilities...)
	}

	comps, err := mergeCDXRecords("component", rawComponents)
	if err != nil {
		return cdxDocument{}, err
	}
	vulns, err := mergeCDXRecords("vulnerability", rawVulns)
	if err != nil {
		return cdxDocument{}, err
	}
	doc.Components = comps
	doc.Vulnerabilities = vulns
	return doc, nil
}

// cdxGroup accumulates every raw record sharing one identity key, in
// first-seen order, so output ordering stays deterministic across runs.
type cdxGroup struct {
	key  string
	objs []map[string]any
}

// mergeCDXRecords merges one CycloneDX array (components or vulnerabilities)
// across all inputs. kind is "component" or "vulnerability".
func mergeCDXRecords(kind string, raws []json.RawMessage) ([]json.RawMessage, error) {
	var keyed []*cdxGroup
	keyIndex := make(map[string]int)
	var unkeyed []map[string]any
	var passthrough []json.RawMessage

	for _, raw := range raws {
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			// Not a JSON object we can reason about — preserve it verbatim
			// rather than silently dropping data.
			passthrough = append(passthrough, raw)
			continue
		}
		key, ok := cdxIdentityKey(kind, obj)
		if !ok {
			unkeyed = append(unkeyed, obj)
			continue
		}
		if idx, exists := keyIndex[key]; exists {
			keyed[idx].objs = append(keyed[idx].objs, obj)
			continue
		}
		keyIndex[key] = len(keyed)
		keyed = append(keyed, &cdxGroup{key: key, objs: []map[string]any{obj}})
	}

	var out []json.RawMessage
	for _, g := range keyed {
		merged, err := mergeCDXGroup(kind, g.key, g.objs)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("cyclonedx: marshal merged %s %q: %w", kind, g.key, err)
		}
		out = append(out, json.RawMessage(b))
	}

	// Records with no safe identity are kept distinct unless they are
	// semantically (byte-for-byte, after canonical re-marshal) identical —
	// we never merge complementary data across records we cannot prove
	// describe the same thing.
	seen := make(map[string]bool)
	for _, obj := range unkeyed {
		b, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		c := string(b)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, json.RawMessage(b))
	}

	if len(passthrough) > 0 {
		rawSeen := make(map[string]bool)
		for _, raw := range passthrough {
			c := string(raw)
			if rawSeen[c] {
				continue
			}
			rawSeen[c] = true
			out = append(out, raw)
		}
	}

	return out, nil
}

// cdxIdentityKey resolves the safe identity of one component or vulnerability
// record. For a component: non-empty purl; then non-empty bom-ref; then a
// deterministic package tuple (type, group, name, version) when name is
// present. For a vulnerability: non-empty bom-ref, then id. ok is false when no
// field yields a safe identity.
//
// purl outranks bom-ref for components, and that order is the fix for a merge
// that was doing nothing at all.
//
// A bom-ref is defined by the spec as an identifier "used to reference the
// component elsewhere in the BOM" — it is scoped to the document that declares
// it and carries no meaning outside it. Trivy stamps a fresh random UUID on
// every occurrence, so a package referenced by several projects can arrive as
// several records with distinct bom-refs. Reading bom-ref first made each one
// its own identity and the merge a no-op: a consumer run's component count was
// inflated nearly 5x relative to its distinct dependencies. A purl is the opposite — a
// cross-document coordinate, which is the entire reason the field exists.
//
// This is safe here because a bom-ref in the merged document references
// nothing: cdxDocument has no dependencies graph, so no producer's graph
// survives the merge to be broken by collapsing refs. Adding one means
// revisiting this — the graph would have to be rewritten through the same
// identity map, not merged beside it.
func cdxIdentityKey(kind string, obj map[string]any) (key string, ok bool) {
	switch kind {
	case "component":
		if purl, present := nonEmptyCDXString(obj["purl"]); present {
			return "purl\x00" + purl, true
		}
		if ref, present := nonEmptyCDXString(obj["bom-ref"]); present {
			return "bom-ref\x00" + ref, true
		}
		name, hasName := nonEmptyCDXString(obj["name"])
		if !hasName {
			return "", false
		}
		typ, _ := nonEmptyCDXString(obj["type"])
		group, _ := nonEmptyCDXString(obj["group"])
		version, _ := nonEmptyCDXString(obj["version"])
		return fmt.Sprintf("tuple\x00%s\x00%s\x00%s\x00%s", typ, group, name, version), true
	case "vulnerability":
		// Unchanged order. A vulnerability has no purl, and its bom-ref is the
		// only identity a producer that emits one intends to be honoured.
		if ref, present := nonEmptyCDXString(obj["bom-ref"]); present {
			return "bom-ref\x00" + ref, true
		}
		if id, present := nonEmptyCDXString(obj["id"]); present {
			return "id\x00" + id, true
		}
	}
	return "", false
}

func nonEmptyCDXString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// cdxDocumentLocalFields are fields whose value means something only inside the
// document that produced it. Two records proven to be the same package may
// legitimately carry different values, so the first-seen one wins instead of
// being reported as a conflict.
//
// bom-ref is the only member, and it is here because the purl-first identity
// above guarantees the collision: repeated records for one package arrive with
// distinct Trivy-generated UUIDs, and treating that as "conflicting values" —
// which is what mergeCDXValue does for every other differing scalar, correctly
// — would fail the whole merge on the exact input this change exists to fold.
//
// First-seen rather than dropped, because CycloneDX wants components
// addressable and a merged record with no ref is less useful than one with an
// arbitrary but stable ref. Deterministic because keyed groups preserve
// first-seen order.
var cdxDocumentLocalFields = map[string]bool{"bom-ref": true}

// mergeCDXGroup folds every record sharing one identity into a single
// record, field by field.
func mergeCDXGroup(kind, key string, objs []map[string]any) (map[string]any, error) {
	merged := map[string]any{}
	for _, obj := range objs {
		for k, v := range obj {
			existing, present := merged[k]
			if !present {
				merged[k] = v
				continue
			}
			if cdxDocumentLocalFields[k] {
				continue
			}
			mv, err := mergeCDXValue(k, existing, v)
			if err != nil {
				return nil, fmt.Errorf("cyclonedx: conflicting %s %q: %w", kind, key, err)
			}
			merged[k] = mv
		}
	}
	return merged, nil
}

// mergeCDXValue merges two values for the same field. Equal values collapse
// trivially. Arrays union with dedup; objects merge recursively; a scalar
// present on only one side wins, but two different non-empty scalars are a
// genuine conflict and return an error instead of picking one silently.
func mergeCDXValue(field string, a, b any) (any, error) {
	if reflect.DeepEqual(a, b) {
		return a, nil
	}
	switch av := a.(type) {
	case []any:
		bv, ok := b.([]any)
		if !ok {
			if isEmptyCDXScalar(b) {
				return av, nil
			}
			return nil, fmt.Errorf("field %q: type mismatch (array vs %T)", field, b)
		}
		return unionCDXArrays(av, bv), nil
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			if isEmptyCDXScalar(b) {
				return av, nil
			}
			return nil, fmt.Errorf("field %q: type mismatch (object vs %T)", field, b)
		}
		out := make(map[string]any, len(av))
		for k, v := range av {
			out[k] = v
		}
		for k, v := range bv {
			existing, present := out[k]
			if !present {
				out[k] = v
				continue
			}
			mv, err := mergeCDXValue(field+"."+k, existing, v)
			if err != nil {
				return nil, err
			}
			out[k] = mv
		}
		return out, nil
	case nil:
		return b, nil
	default:
		if isEmptyCDXScalar(a) {
			return b, nil
		}
		if isEmptyCDXScalar(b) {
			return a, nil
		}
		return nil, fmt.Errorf("field %q: conflicting values %v vs %v", field, a, b)
	}
}

func isEmptyCDXScalar(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	}
	return false
}

// unionCDXArrays concatenates a and b, deduping elements that are
// semantically identical (compared via their canonical JSON encoding) and
// preserving first-seen order.
func unionCDXArrays(a, b []any) []any {
	out := make([]any, 0, len(a))
	seen := make(map[string]bool, len(a))
	add := func(items []any) {
		for _, v := range items {
			c, err := json.Marshal(v)
			key := string(c)
			if err != nil {
				key = fmt.Sprintf("%v", v)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, v)
		}
	}
	add(a)
	add(b)
	return out
}
