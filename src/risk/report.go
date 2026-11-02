package main

import (
	"fmt"
	"strings"
	"time"
)

var statusOrder = []string{"needs_review", "approved", "accepted_risk", "rejected"}

func renderReport(findings []Finding, decisions map[string]Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Risk Report\n\nGenerated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	statusSet := make(map[string]bool, len(statusOrder))
	for _, s := range statusOrder {
		statusSet[s] = true
	}
	byStatus := make(map[string][]Finding)
	for _, f := range findings {
		status := "needs_review"
		if d, ok := decisions[f.ID]; ok {
			if d.Status != "" && statusSet[d.Status] {
				status = d.Status
			}
		}
		byStatus[status] = append(byStatus[status], f)
	}
	for _, status := range statusOrder {
		ff := byStatus[status]
		if len(ff) == 0 {
			continue
		}
		label := strings.ReplaceAll(status, "_", " ")
		fmt.Fprintf(&b, "## %s (%d)\n\n", label, len(ff))
		for _, f := range ff {
			d := decisions[f.ID]
			fmt.Fprintf(&b, "### %s — %s\n\n", f.ID, f.Title)
			fmt.Fprintf(&b, "- **Category:** %s\n", f.Category)
			fmt.Fprintf(&b, "- **Severity:** %s\n", f.Severity)
			fmt.Fprintf(&b, "- **Confidence:** %.0f%%\n", f.Confidence*100)
			fmt.Fprintf(&b, "- **Location:** `%s` lines %d–%d\n\n", f.Evidence.File, f.Evidence.StartLine, f.Evidence.EndLine)
			if f.Evidence.Snippet != "" {
				fmt.Fprintf(&b, "```\n%s\n```\n\n", f.Evidence.Snippet)
			}
			if d.Justification != "" {
				fmt.Fprintf(&b, "> %s — *%s, %s*\n\n", d.Justification, d.ReviewedBy, d.ReviewedAt)
			}
		}
	}
	return b.String()
}
