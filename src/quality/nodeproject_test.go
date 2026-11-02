//go:build unit_test

package main

import (
	"strings"
	"testing"
)

// defaultNodeProjectLimit mirrors the `+default=4` pragma on Check's
// node-project-limit parameter; the pragma is the only place the default lives.
const defaultNodeProjectLimit = 4

func TestNodeProjectDirs(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  []string
	}{{
		name:  "root package.json wins outright",
		lines: []string{"/src/package.json", "/src/Client/package.json", "/src/Server/package.json"},
		// A workspace root's config governs the whole tree and its node_modules
		// holds the hoisted ESLint. Linting each package separately would install
		// four times and lint under configs the root overrides.
		want: []string{"."},
	}, {
		name:  "nested single project is linted where it lives",
		lines: []string{"/src/Client/package.json"},
		// A synthetic nested layout: node must not be detected here and then
		// linted at /src, which has no package.json.
		want: []string{"Client"},
	}, {
		name:  "sibling projects at equal depth are both linted",
		lines: []string{"/src/Client/package.json", "/src/Server/package.json"},
		want:  []string{"Client", "Server"},
	}, {
		name:  "mixed-depth siblings are independent projects",
		lines: []string{"/src/apps/web/package.json", "/src/Client/package.json"},
		want:  []string{"Client", "apps/web"},
	}, {
		name: "a four-application mixed-depth layout keeps all four applications",
		lines: []string{
			"/src/admin-ui/package.json",
			"/src/demo/apps/web/package.json",
			"/src/sample-dashboard/package.json",
			"/src/worker-ui/package.json",
		},
		want: []string{
			"admin-ui",
			"demo/apps/web",
			"sample-dashboard",
			"worker-ui",
		},
	}, {
		name: "a package-bearing ancestor governs its nested packages",
		lines: []string{
			"/src/apps/web/package.json",
			"/src/services/api/package.json",
			"/src/apps/package.json",
		},
		want: []string{"apps", "services/api"},
	}, {
		name: "dependency trees are never projects",
		lines: []string{
			"/src/node_modules/eslint/package.json",
			"/src/Client/node_modules/react/package.json",
			"/src/bower_components/jquery/package.json",
			"/src/.yarn/cache/lodash/package.json",
			"/src/Client/package.json",
		},
		want: []string{"Client"},
	}, {
		name: "a dependency tree cannot become the only project",
		// Without the vendor filter this returns node_modules/eslint and cicd
		// lints its own linter's source.
		lines: []string{"/src/node_modules/eslint/package.json"},
		want:  []string{},
	}, {
		name: "other marker files are ignored",
		lines: []string{
			"/src/go.mod",
			"/src/api/api.csproj",
			"/src/requirements.txt",
			"/src/Client/package.json",
		},
		want: []string{"Client"},
	}, {
		name:  "no node markers at all",
		lines: []string{"/src/go.mod", "/src/pyproject.toml"},
		want:  []string{},
	}, {
		name:  "blank and truncated lines survive",
		lines: []string{"", "   ", "/src/Client/package.json", ""},
		want:  []string{"Client"},
	}, {
		name: "paths outside the mount are dropped",
		// find output should never contain these, but a rewritten prefix would
		// silently produce a workdir that does not exist.
		lines: []string{"/other/package.json", "/srcx/package.json", "/src/Client/package.json"},
		want:  []string{"Client"},
	}, {
		name:  "build output is not excluded",
		lines: []string{"/src/dist/package.json"},
		// Deliberate: excluding a directory means reporting less than the tree
		// holds. A repo that generates dist/ normally has a package-bearing
		// ancestor; without one, ESLint's own ignore config is the consumer's lever.
		want: []string{"dist"},
	}, {
		name:  "duplicate lines collapse",
		lines: []string{"/src/Client/package.json", "/src/Client/package.json"},
		want:  []string{"Client"},
	}, {
		name:  "trailing-slash root is normalised",
		lines: []string{"/src/package.json"},
		want:  []string{"."},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nodeProjectDirs("/src", tc.lines)
			if len(got) != len(tc.want) {
				t.Fatalf("nodeProjectDirs = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("nodeProjectDirs = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestNodeProjectDirsRootWithTrailingSlash(t *testing.T) {
	// srcMount is a constant today, but a caller passing "/src/" must not turn
	// every project into an unresolvable path.
	got := nodeProjectDirs("/src/", []string{"/src/Client/package.json"})
	if len(got) != 1 || got[0] != "Client" {
		t.Fatalf("nodeProjectDirs = %v, want [Client]", got)
	}
}

func TestNodeProjectLimitError(t *testing.T) {
	within := []string{"a", "b", "c", "d"}
	if msg := nodeProjectLimitError(within, defaultNodeProjectLimit); msg != "" {
		t.Fatalf("%d projects is within the limit, got error %q", len(within), msg)
	}

	over := []string{"a", "b", "c", "d", "e"}
	msg := nodeProjectLimitError(over, defaultNodeProjectLimit)
	if msg == "" {
		t.Fatal("5 projects exceeds the limit but produced no error — a truncated lint would read as clean")
	}
	// The count and the offenders both belong in the message: the consumer has to
	// be able to tell which projects went unlinted without reading a container log.
	for _, want := range []string{"5", "a, b, c, d, e", "--node-project-limit", "application-scoped"} {
		if !strings.Contains(msg, want) {
			t.Errorf("limit error missing %q: %s", want, msg)
		}
	}
}

func TestMergeEslintVersions(t *testing.T) {
	cases := []struct {
		name string
		raw  []string
		want string
	}{
		{"single project", []string{"v9.39.5\n"}, "9.39.5"},
		{"agreeing projects collapse", []string{"v9.39.5\n", "9.39.5"}, "9.39.5"},
		{"disagreeing projects are both reported", []string{"v9.39.5\n", "v8.57.1\n"}, "8.57.1,9.39.5"},
		{"nothing resolved", []string{"", "\n"}, "unknown"},
		// A version that could not be read must not be papered over by a sibling
		// that could — but it must not erase the one that did either.
		{"one unknown among known", []string{"", "v9.39.5\n"}, "9.39.5"},
		{"garbage is unknown, not a fake version", []string{"sh: eslint: not found\n"}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeEslintVersions(tc.raw); got != tc.want {
				t.Fatalf("mergeEslintVersions(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMergeNodeCoverage(t *testing.T) {
	t.Run("no projects reported coverage", func(t *testing.T) {
		pct, lines := mergeNodeCoverage(nil)
		if pct != nil || lines != nil {
			t.Fatalf("got %v/%v, want nil/nil — an absent reading must not become 0%%", pct, lines)
		}
	})

	t.Run("single project passes straight through", func(t *testing.T) {
		pct, lines := mergeNodeCoverage([]nodeCoverage{{Percent: 82.5, Lines: 200}})
		if pct == nil || *pct != 82.5 {
			t.Fatalf("pct = %v, want 82.5", pct)
		}
		if lines == nil || *lines != 200 {
			t.Fatalf("lines = %v, want 200", lines)
		}
	})

	t.Run("weighted by coverable lines, not averaged", func(t *testing.T) {
		// The false pass this guards: an unweighted mean of 100 and 40 is 70,
		// which would clear a 60% gate the 5000-line project fails outright.
		pct, lines := mergeNodeCoverage([]nodeCoverage{
			{Percent: 100, Lines: 5},
			{Percent: 40, Lines: 5000},
		})
		want := (100*5.0 + 40*5000.0) / 5005.0
		if pct == nil || *pct != want {
			t.Fatalf("pct = %v, want %v", pct, want)
		}
		if *pct > 60 {
			t.Fatalf("pct = %v clears a 60%% gate the 5000-line project fails", *pct)
		}
		if lines == nil || *lines != 5005 {
			t.Fatalf("lines = %v, want 5005 — the ratchet's min-lines guard reads this", lines)
		}
	})

	t.Run("zero-line projects carry no weight", func(t *testing.T) {
		pct, lines := mergeNodeCoverage([]nodeCoverage{
			{Percent: 0, Lines: 0},
			{Percent: 90, Lines: 100},
		})
		if pct == nil || *pct != 90 {
			t.Fatalf("pct = %v, want 90 — a project with no coverable lines must not dilute", pct)
		}
		if lines == nil || *lines != 100 {
			t.Fatalf("lines = %v, want 100", lines)
		}
	})

	t.Run("all zero-line falls back to the plain mean with no line total", func(t *testing.T) {
		// Degenerate, but it is exactly what the single-project path did before:
		// report the percentage, omit CoverageLines so the ratchet's min-lines
		// guard does not read a fabricated zero.
		pct, lines := mergeNodeCoverage([]nodeCoverage{{Percent: 100, Lines: 0}})
		if pct == nil || *pct != 100 {
			t.Fatalf("pct = %v, want 100", pct)
		}
		if lines != nil {
			t.Fatalf("lines = %v, want nil", lines)
		}
	})
}

func TestNodeProjectLabel(t *testing.T) {
	// Root stays unprefixed so the single-project case — and the remedy strings
	// eslintRunError writes — read exactly as they did before.
	if got := nodeProjectLabel(".", "eslint: did not run"); got != "eslint: did not run" {
		t.Fatalf("root label = %q", got)
	}
	if got := nodeProjectLabel("Client", "eslint: did not run"); got != "Client: eslint: did not run" {
		t.Fatalf("nested label = %q", got)
	}
}

func TestConsumerNodeProjectBudget(t *testing.T) {
	projects := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	if nodeProjectLimitError(projects, 4) == "" {
		t.Fatal("default budget bypassed")
	}
	if msg := nodeProjectLimitError(projects, 20); msg != "" {
		t.Fatal(msg)
	}
	for _, n := range []int{-1, 0} {
		if validateNodeProjectLimit(n) == nil {
			t.Fatal("invalid budget accepted")
		}
	}
}
