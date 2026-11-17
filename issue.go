package main

import (
	"fmt"
	"regexp"
	"strings"
)

// GitHub rejects issues whose title or body exceed these lengths (in characters).
const (
	maxTitleLength = 256
	maxBodyLength  = 65536
)

const issueFooter = "> This issue was created automatically by dt-github-notifier.\n"

func buildPolicyViolationIssue(s policyViolationSubject) gitHubIssueRequest {
	v := s.PolicyViolation
	policy := v.Condition.Policy

	title := fmt.Sprintf("[DT] Policy Violation: %s in %s", policy.Name, projectName(s.Project))

	var body strings.Builder
	body.WriteString("## :rotating_light: Policy Violation Detected\n\n")
	body.WriteString("| Field | Value |\n|---|---|\n")
	writeRow(&body, "Project", projectName(s.Project))
	writeRow(&body, "Component", componentName(s.Component))
	writeRow(&body, "Policy", policy.Name)
	writeRow(&body, "Violation State", policy.ViolationState)
	writeRow(&body, "Type", v.Type)
	writeRow(&body, "Condition", strings.Join([]string{v.Condition.Subject, v.Condition.Operator, v.Condition.Value}, " "))
	writeRow(&body, "Timestamp", v.Timestamp)
	if v.Message != "" {
		fmt.Fprintf(&body, "\n**Message:**\n%s\n", block(v.Message))
	}
	body.WriteString("\n" + issueFooter)

	return newIssue(title, body.String(), []string{
		"security",
		"policy-violation",
		"dependency-track",
		"violation-state:" + strings.ToLower(policy.ViolationState),
	})
}

func buildNewVulnerabilityIssue(s newVulnerabilitySubject) gitHubIssueRequest {
	v := s.Vulnerability

	title := fmt.Sprintf("[DT] %s (%s) in %s", v.VulnID, v.Severity, componentName(s.Component))

	var body strings.Builder
	body.WriteString("## :shield: New Vulnerability Identified\n\n")
	body.WriteString("| Field | Value |\n|---|---|\n")
	writeRow(&body, "CVE / ID", v.VulnID)
	if aliases := aliasIDs(v); aliases != "" {
		writeRow(&body, "Aliases", aliases)
	}
	writeRow(&body, "Source", v.Source)
	writeRow(&body, "Severity", v.Severity)
	writeRow(&body, "CVSS Score", cvssScore(v))
	writeRow(&body, "Project", projectName(s.Project))
	writeRow(&body, "Component", componentName(s.Component))
	if v.Description != "" {
		fmt.Fprintf(&body, "\n**Description:**\n%s\n", block(v.Description))
	}
	if v.Recommendation != "" {
		fmt.Fprintf(&body, "\n**Recommendation:**\n%s\n", block(v.Recommendation))
	}
	body.WriteString("\n" + issueFooter)

	return newIssue(title, body.String(), []string{
		"security",
		"vulnerability",
		"dependency-track",
		"severity:" + strings.ToLower(v.Severity),
	})
}

func buildNewVulnerableDependencyIssue(s newVulnerableDependencySubject) gitHubIssueRequest {
	title := fmt.Sprintf("[DT] Vulnerable Dependency: %s introduced in %s",
		componentName(s.Component), projectName(s.Project))

	var body strings.Builder
	body.WriteString("## :warning: Vulnerable Dependency Introduced\n\n")
	body.WriteString("| Field | Value |\n|---|---|\n")
	writeRow(&body, "Project", projectName(s.Project))
	writeRow(&body, "Component", componentName(s.Component))
	body.WriteString("\n**Vulnerabilities:**\n")
	for _, v := range s.Vulnerabilities {
		fmt.Fprintf(&body, "- **%s** (%s) — %s\n", inline(v.VulnID), inline(v.Severity), inline(v.Source))
	}
	body.WriteString("\n" + issueFooter)

	return newIssue(title, body.String(), []string{"security", "vulnerable-dependency", "dependency-track"})
}

// newIssue neutralises mentions in the title and truncates title and body to
// the lengths GitHub accepts.
func newIssue(title, body string, labels []string) gitHubIssueRequest {
	return gitHubIssueRequest{
		Title:  truncate(inline(title), maxTitleLength),
		Body:   truncate(body, maxBodyLength),
		Labels: labels,
	}
}

func writeRow(b *strings.Builder, field, value string) {
	fmt.Fprintf(b, "| **%s** | %s |\n", field, inline(value))
}

// componentName returns a human-readable component string, e.g. "apache:axis 1.4"
func componentName(c component) string {
	name := c.Name
	if c.Group != "" {
		name = c.Group + ":" + name
	}
	if c.Version != "" {
		name += " " + c.Version
	}
	return name
}

// projectName returns a human-readable project string, e.g. "my-service 1.0.0"
func projectName(p project) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}

func cvssScore(v vulnerability) string {
	switch {
	case v.CVSSv4 > 0:
		return fmt.Sprintf("%.1f (v4)", v.CVSSv4)
	case v.CVSSv3 > 0:
		return fmt.Sprintf("%.1f (v3)", v.CVSSv3)
	case v.CVSSv2 > 0:
		return fmt.Sprintf("%.1f (v2)", v.CVSSv2)
	default:
		return "N/A"
	}
}

func aliasIDs(v vulnerability) string {
	ids := make([]string, 0, len(v.Aliases))
	for _, a := range v.Aliases {
		if a.VulnID != "" && a.VulnID != v.VulnID {
			ids = append(ids, a.VulnID)
		}
	}
	return strings.Join(ids, ", ")
}

// mentionPattern matches an "@" that GitHub would render as a user or team
// mention: one not preceded by a word character (so "pkg:npm/a@1.0" is kept).
var mentionPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_])@([A-Za-z0-9])`)

// neutraliseMentions inserts a zero-width space after such an "@" so that
// text coming from Dependency-Track cannot notify GitHub users or teams.
func neutraliseMentions(s string) string {
	return mentionPattern.ReplaceAllString(s, "${1}@\u200b${2}")
}

// inlineReplacer keeps text on a single Markdown table row.
var inlineReplacer = strings.NewReplacer(
	"|", "\\|",
	"\r\n", " ",
	"\n", " ",
	"\r", " ",
)

// inline makes untrusted text safe for a single-line context such as a title
// or a Markdown table cell.
func inline(s string) string { return neutraliseMentions(inlineReplacer.Replace(s)) }

// block makes untrusted multi-line text safe for the issue body.
func block(s string) string { return neutraliseMentions(s) }

// truncate shortens s to at most limit characters, marking the cut with "…".
func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}
