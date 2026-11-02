// Where the findings are, when the list of findings is too long to show and a
// reader needs to know which places to go and fix.
//
// A DAST run against the consumer API published under twenty findings over a swagger
// surface; a bigger one publishes hundreds over a few dozen endpoints. The
// comment shows the first 25 rows and a count of the rest, which answers "how
// many" and never "where" — and for a DAST envelope "where" is the endpoint
// list, the one thing a reviewer of a web scan actually wants.
//
// It is derived from findings[] at render time and stored nowhere. A second
// list written by the producer would be a second thing to keep true; this one
// cannot disagree with the table above it because it is the table above it,
// counted differently.
package main

import (
	"fmt"
	"sort"
	"strings"
)

// maxRolledUpLocations caps the rollup for the same reason maxRenderedFindings
// caps the detail table — GitHub's comment-size limit is shared by both, and a
// rollup longer than the list it summarises has stopped summarising.
const maxRolledUpLocations = 25

// locationGroup is one place, and what was found there.
type locationGroup struct {
	Path string
	// Worst is the most severe finding at this location. A location with one
	// HIGH is a different errand from a location with forty LOWs, and a rollup
	// ordered only by count would put the second first.
	Worst Severity
	Count int
	// first is where this location appeared in the envelope's order, used only
	// to break count ties. See groupByLocation.
	first int
}

// groupByLocation counts findings per location, in the order the rollup renders.
//
// Unlocated findings are counted and returned separately rather than grouped
// under an empty path or attached to the nearest one. A producer that reported
// no location has said something, and the rollup's job is to say where things
// are — inventing a location for a finding that has none is the one thing it
// must not do to stay readable.
//
// The order is by count descending, ties broken by first appearance and never
// alphabetically. The envelope's order is most-severe-first (the aggregator
// decides it once and writeFindingsDetail states that rule in its truncation
// note), so first-appearance carries severity into the tie-break for free,
// while an alphabetical tie-break would discard it and sort /api/a above a
// critical /api/z. Deterministic either way; only one of them is informative.
func groupByLocation(findings []Finding) (groups []locationGroup, unlocated int) {
	index := map[string]int{}
	for _, f := range findings {
		path := findingLocationPath(f)
		if path == "" {
			unlocated++
			continue
		}
		if i, ok := index[path]; ok {
			groups[i].Count++
			if severityOrder(f.Severity) > severityOrder(groups[i].Worst) {
				groups[i].Worst = f.Severity
			}
			continue
		}
		index[path] = len(groups)
		groups = append(groups, locationGroup{
			Path: path, Worst: f.Severity, Count: 1, first: len(groups),
		})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].first < groups[j].first
	})
	return groups, unlocated
}

// findingLocationPath is the location a rollup groups on: the path without the
// line.
//
// Deliberately not findingLocation, which renders path:line for the detail
// table. Three findings on three lines of one file are one file to open, and
// in a DAST envelope the path IS the endpoint — ZAP writes the instance URI
// there and reports no line at all, so keeping the line would be a no-op for
// the case this exists for and a de-grouping for every other.
func findingLocationPath(f Finding) string {
	return strings.TrimSpace(f.ArtifactPath)
}

// writeLocationRollup renders the per-location table, when it says something
// the finding table does not.
//
// Two conditions, either of which is enough:
//
//   - the detail table is truncated, so there are locations in the envelope
//     that no rendered row names; or
//   - grouping compresses, so the rollup is shorter than the list and tells a
//     reader at a glance that 40 findings are 3 endpoints.
//
// When neither holds — every finding on its own location, all of them shown —
// the rollup would be the same rows in the same order with a count of 1 in
// every line, which is the shape of a section a reader learns to skip. Silence
// where an absence carries nothing, a line where it carries something: the
// same call webdisclose.go documents, one module over.
func writeLocationRollup(sb *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		return
	}
	groups, unlocated := groupByLocation(findings)
	distinct := len(groups)
	if unlocated > 0 {
		distinct++
	}
	if len(findings) <= maxRenderedFindings && distinct >= len(findings) {
		return
	}

	sb.WriteString("\n**Findings by location:**\n\n")
	sb.WriteString("| Location | Worst | Findings |\n")
	sb.WriteString("|----------|-------|----------|\n")
	shown := groups
	if len(shown) > maxRolledUpLocations {
		shown = shown[:maxRolledUpLocations]
	}
	for _, g := range shown {
		fmt.Fprintf(sb, "| %s | %s | %s |\n",
			cellCode(g.Path), cellOrDash(string(g.Worst)), humanCount(g.Count))
	}
	// Counted, never dropped and never folded into a location: a finding whose
	// producer stated no location is still a finding, and a rollup that quietly
	// omitted it would under-count the very total it is summarising.
	if unlocated > 0 {
		fmt.Fprintf(sb, "| _no location stated_ | — | %s |\n", humanCount(unlocated))
	}
	if extra := len(groups) - maxRolledUpLocations; extra > 0 {
		fmt.Fprintf(sb, "\n_+%d more location(s); the %d shown are those with the most findings._\n",
			extra, maxRolledUpLocations)
	}
}
