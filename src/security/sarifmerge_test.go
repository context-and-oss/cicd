package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func sarifRuns(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	var doc struct {
		Schema  string            `json:"$schema"`
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("merged document is not JSON: %v\n%s", err, raw)
	}
	if doc.Schema != "s" || doc.Version != "2.1.0" {
		t.Fatalf("merged header %q/%q: want the first document's", doc.Schema, doc.Version)
	}
	return doc.Runs
}

func TestMergeSARIF(t *testing.T) {
	a := json.RawMessage(`{"$schema":"s","version":"2.1.0","runs":[{"tool":"a"}]}`)
	b := json.RawMessage(`{"$schema":"other","version":"2.0.0","runs":[{"tool":"b"},{"tool":"b2"}]}`)

	t.Run("nil sides pass the other through untouched", func(t *testing.T) {
		if got := mergeSARIF(nil, b); string(got) != string(b) {
			t.Fatalf("nil+b = %s", got)
		}
		if got := mergeSARIF(a, nil); string(got) != string(a) {
			t.Fatalf("a+nil = %s", got)
		}
	})
	t.Run("runs concatenate in order under the first header", func(t *testing.T) {
		runs := sarifRuns(t, mergeSARIF(a, b))
		if len(runs) != 3 || string(runs[0]) != `{"tool":"a"}` || string(runs[2]) != `{"tool":"b2"}` {
			t.Fatalf("runs = %s", runs)
		}
	})
	t.Run("two null run arrays become an empty array, never null", func(t *testing.T) {
		got := mergeSARIF(json.RawMessage(`{"$schema":"s","version":"2.1.0"}`), json.RawMessage(`{"runs":null}`))
		runs := sarifRuns(t, got)
		if runs == nil || len(runs) != 0 {
			t.Fatalf("runs = %#v (%s)", runs, got)
		}
	})
	t.Run("an unreadable side leaves the first document alone", func(t *testing.T) {
		if got := mergeSARIF(a, json.RawMessage(`not json`)); string(got) != string(a) {
			t.Fatalf("a+garbage = %s", got)
		}
		if got := mergeSARIF(json.RawMessage(`not json`), b); string(got) != "not json" {
			t.Fatalf("garbage+b = %s", got)
		}
	})
}

func TestMergeSARIFFoldsInOrder(t *testing.T) {
	doc := func(id string) json.RawMessage {
		return json.RawMessage(`{"$schema":"s","version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + id + `"}}}]}`)
	}
	got := mergeSARIF(doc("a"), nil, doc("b"), doc("c"))
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range parsed.Runs {
		names = append(names, r.Tool.Driver.Name)
	}
	if strings.Join(names, ",") != "a,b,c" {
		t.Errorf("runs = %v, want a,b,c", names)
	}
	if mergeSARIF() != nil || mergeSARIF(nil, nil) != nil {
		t.Error("merging nothing must be nil")
	}
}
