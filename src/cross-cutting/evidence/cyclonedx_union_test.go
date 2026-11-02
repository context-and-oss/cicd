package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUnionCDXArraysPreservesOrderAndInputs(t *testing.T) {
	tests := []struct {
		name string
		a, b []any
		want []any
	}{
		{name: "nil inputs", want: []any{}},
		{name: "empty inputs", a: []any{}, b: []any{}, want: []any{}},
		{name: "first only", a: []any{"alpha", "beta"}, want: []any{"alpha", "beta"}},
		{name: "second only", b: []any{"alpha", "beta"}, want: []any{"alpha", "beta"}},
		{name: "second grows output", a: []any{"alpha"}, b: []any{"beta", "gamma", "delta"}, want: []any{"alpha", "beta", "gamma", "delta"}},
		{name: "overlap and repeated elements", a: []any{"beta", "alpha", "beta"}, b: []any{"alpha", "gamma", "gamma"}, want: []any{"beta", "alpha", "gamma"}},
		{
			name: "canonical objects and distinct scalar types",
			a:    []any{map[string]any{"name": "alpha", "version": "1"}, nil, float64(1)},
			b:    []any{map[string]any{"version": "1", "name": "alpha"}, nil, "1"},
			want: []any{map[string]any{"name": "alpha", "version": "1"}, nil, float64(1), "1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := cdxUnionJSON(t, []any{tt.a, tt.b})
			got := unionCDXArrays(tt.a, tt.b)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("unionCDXArrays() = %#v, want %#v", got, tt.want)
			}
			if after := cdxUnionJSON(t, []any{tt.a, tt.b}); after != before {
				t.Fatalf("inputs changed: before %s, after %s", before, after)
			}
		})
	}
}

func TestMergeCDXValueObjectUnionPreservesInputs(t *testing.T) {
	a := map[string]any{
		"name": "alpha",
		"details": map[string]any{
			"left":   "first",
			"labels": []any{"shared", "first"},
		},
	}
	b := map[string]any{
		"version": "1",
		"details": map[string]any{
			"right":  "second",
			"labels": []any{"shared", "second", "third"},
		},
	}
	before := cdxUnionJSON(t, []any{a, b})
	got, err := mergeCDXValue("component", a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name":    "alpha",
		"version": "1",
		"details": map[string]any{
			"left":   "first",
			"right":  "second",
			"labels": []any{"shared", "first", "second", "third"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeCDXValue() = %#v, want %#v", got, want)
	}
	if after := cdxUnionJSON(t, []any{a, b}); after != before {
		t.Fatalf("inputs changed: before %s, after %s", before, after)
	}
}

func cdxUnionJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
