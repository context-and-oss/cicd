// Which files the pylint leg lints, decided by cicd rather than by pylint.
//
// Deliberately untagged: the selection is a pure function of the tree's file
// list, so `go test -tags unit_test` reaches it.
//
// The leg used to run `pylint .`. pylint treats a directory argument as one
// package: on a flat tree with no __init__.py at its root it printed a single
// F0010 parse-error and linted nothing (measured, pylint 3.1.0 on
// testdata/python-app), and on a tree that is a package it skipped every
// directory below it that is not. `--recursive=y` reaches them, but also walks
// into .venv, node_modules and every hidden directory, and reports a
// modulesLinted that is not a file count. So cicd lists the files itself: the
// list is the scope, and its length is the denominator Examined reports.

package main

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// pylintTargetGlob and pylintVenvGlob are what the leg asks the source
// directory for. A virtualenv is recognised by its pyvenv.cfg, so one named
// anything — env/, venv/, .direnv/python-3.12/ — is pruned by what it is, not
// by a name list that will miss the next one.
const (
	pylintTargetGlob = "**/*.py"
	pylintVenvGlob   = "**/pyvenv.cfg"
)

// pylintPrunedLabel names what pylintTargets drops, for the warning that says
// how many files it dropped. Narrowing the scope must be named.
const pylintPrunedLabel = "hidden directories, node_modules, __pycache__, site-packages and virtualenvs"

// pylintTargets returns the files to lint, sorted, and how many .py files it
// pruned. A path is pruned when any directory on it is hidden (.venv, .tox,
// .git), is node_modules, __pycache__ or site-packages, or holds a pyvenv.cfg.
// Every target is prefixed "./" so none can be read by pylint as an option.
func pylintTargets(pyFiles, venvCfgs []string) ([]string, int) {
	venvs := map[string]bool{}
	for _, c := range venvCfgs {
		venvs[path.Dir(path.Clean(c))] = true
	}
	var targets []string
	pruned := 0
	for _, f := range pyFiles {
		f = path.Clean(strings.TrimPrefix(f, "./"))
		if f == "." || f == "" || strings.HasPrefix(f, "../") {
			continue
		}
		if pylintPruned(f, venvs) {
			pruned++
			continue
		}
		targets = append(targets, "./"+f)
	}
	sort.Strings(targets)
	return targets, pruned
}

func pylintPruned(file string, venvs map[string]bool) bool {
	dir := path.Dir(file)
	for d := dir; d != "." && d != "/"; d = path.Dir(d) {
		if venvs[d] {
			return true
		}
		switch base := path.Base(d); {
		case strings.HasPrefix(base, "."), base == "node_modules", base == "__pycache__", base == "site-packages":
			return true
		}
	}
	return false
}

// pylintTargetWarnings says what the selection did to the scope: how many
// files were pruned and why, and that nothing was left when nothing was.
func pylintTargetWarnings(targets []string, pruned int) []string {
	var w []string
	if pruned > 0 {
		w = append(w, "pylint: skipped "+strconv.Itoa(pruned)+" .py file(s) under "+pylintPrunedLabel)
	}
	if len(targets) == 0 {
		w = append(w, "pylint: SKIPPED — no .py file to lint outside "+pylintPrunedLabel+
			"; Python was detected by its project files alone")
	}
	return w
}

// pylintScript runs pylint over the target list in targetsPath, one path per
// NUL-separated entry. The list goes through a file rather than argv so a large
// tree cannot exceed the kernel's argument limit, and through pylint's own
// entry point so the arguments reach it exactly as listed.
func pylintScript(targetsPath string) string {
	return "import sys\n" +
		"from pylint.lint import Run\n" +
		"targets = [t for t in open(" + strconv.Quote(targetsPath) + ", encoding='utf-8').read().split('\\0') if t]\n" +
		"Run(['--output-format=json2', '--exit-zero', *targets])\n"
}

// capPaths joins at most n paths and says how many it left out.
func capPaths(paths []string, n int) string {
	if len(paths) <= n {
		return strings.Join(paths, ", ")
	}
	return strings.Join(paths[:n], ", ") + " and " + strconv.Itoa(len(paths)-n) + " more"
}

// lintOutcome is scanOutcome for a lint leg that says how much it read: a run
// that read nothing is SKIPPED, not CLEAN, because zero findings over zero
// files is not a lint. Only CLEAN is downgraded, the same rule risk's
// skippedIfNothingExamined follows.
func lintOutcome(ran bool, findings int, examined *Examined) Outcome {
	o := scanOutcome(ran, findings)
	if o == OutcomeClean && examined != nil && examined.Count == 0 {
		return OutcomeSkipped
	}
	return o
}
