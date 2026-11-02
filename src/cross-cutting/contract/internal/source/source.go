// Package source contains the stdlib-only helpers the contract verifier uses
// to enumerate and parse a module's Go source files.
//
// It lives in its own subpackage so it can be unit-tested with plain `go test`
// — the contract module's main package imports the Dagger SDK, whose init
// function panics outside a Dagger session, which prevents tests from running
// against package main directly.
package source

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// Select returns the subset of directory entries that should be parsed for
// signature verification: regular .go files, excluding the Dagger SDK's
// generated client (dagger.gen.go) and any test files (*_test.go).
// Entry order is preserved so callers can rely on it for deterministic parsing.
func Select(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, name := range entries {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if name == "dagger.gen.go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// FuncParams parses every supplied Go source file and returns a map of
// lowercase param name → Go type for the first function or method named
// funcName. Files are searched in alphabetical order for determinism.
func FuncParams(funcName string, sources map[string]string) (map[string]string, error) {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	fset := token.NewFileSet()
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName {
				continue
			}
			params := make(map[string]string)
			if fn.Type.Params == nil {
				return params, nil
			}
			for _, field := range fn.Type.Params.List {
				typ := exprString(field.Type)
				for _, n := range field.Names {
					params[strings.ToLower(n.Name)] = typ
				}
			}
			return params, nil
		}
	}
	return nil, fmt.Errorf("function %q not found in module sources", funcName)
}

// exprString converts a Go AST type expression to a normalised string.
func exprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	default:
		return fmt.Sprintf("%T", expr)
	}
}
