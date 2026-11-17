// Package issue renders GitHub issues for Dependency-Track notifications.
//
// Issue bodies are Markdown, rendered from the templates in templates/. All
// values coming from Dependency-Track are untrusted and must go through the
// cell (single line, e.g. table cells) or text (multi-line) template
// functions, which neutralize @-mentions and keep the Markdown structure intact.
package issue

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/thomasvitale/dt-github-notifier/internal/notification"
)

// GitHub rejects issues whose title or body exceed these lengths (in characters).
const (
	maxTitleLength = 256
	maxBodyLength  = 65536
)

// Issue is a GitHub issue to create.
type Issue struct {
	Title  string
	Body   string
	Labels []string
	// Key identifies the finding the issue is about, so that repeated
	// notifications for it can be recognized. It is part of Body.
	Key string
}

// keyPrefix starts every Key, making keys easy to search for.
const keyPrefix = "dtgn-"

//go:embed templates/*.md.tmpl
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"cell":          inline,
	"text":          block,
	"aliases":       aliasIDs,
	"cvss":          cvssScore,
	"componentName": componentName,
	"projectName":   projectName,
}).ParseFS(templateFS, "templates/*.md.tmpl"))

func ForPolicyViolation(s notification.PolicyViolationSubject) (Issue, error) {
	policy := s.PolicyViolation.Condition.Policy
	key := newKey("policy-violation", s.Project.UUID, s.Component.UUID, s.PolicyViolation.Condition.UUID)
	return render("policy_violation.md.tmpl", s, key,
		fmt.Sprintf("[DT] Policy Violation: %s in %s", policy.Name, projectName(s.Project)),
		[]string{
			"security",
			"policy-violation",
			"dependency-track",
			"violation-state:" + strings.ToLower(policy.ViolationState),
		})
}

func ForNewVulnerability(s notification.NewVulnerabilitySubject) (Issue, error) {
	v := s.Vulnerability
	key := newKey("new-vulnerability", s.Project.UUID, s.Component.UUID, v.Source, v.VulnID)
	return render("new_vulnerability.md.tmpl", s, key,
		fmt.Sprintf("[DT] %s (%s) in %s", v.VulnID, v.Severity, componentName(s.Component)),
		[]string{
			"security",
			"vulnerability",
			"dependency-track",
			"severity:" + strings.ToLower(v.Severity),
		})
}

func ForNewVulnerableDependency(s notification.NewVulnerableDependencySubject) (Issue, error) {
	key := newKey("new-vulnerable-dependency", s.Project.UUID, s.Component.UUID)
	return render("new_vulnerable_dependency.md.tmpl", s, key,
		fmt.Sprintf("[DT] Vulnerable Dependency: %s introduced in %s", componentName(s.Component), projectName(s.Project)),
		[]string{"security", "vulnerable-dependency", "dependency-track"})
}

// render executes the named body template and appends the footer with the
// key. It neutralizes mentions in the title and truncates title and body to
// the lengths GitHub accepts, keeping the footer so the key stays searchable.
func render(name string, data any, key, title string, labels []string) (Issue, error) {
	var body strings.Builder
	if err := templates.ExecuteTemplate(&body, name, data); err != nil {
		return Issue{}, fmt.Errorf("render %s: %w", name, err)
	}
	footer := fmt.Sprintf("\n> This issue was created automatically by dt-github-notifier (deduplication key: `%s`).\n", key)
	return Issue{
		Title:  truncate(inline(title), maxTitleLength),
		Body:   truncate(body.String(), maxBodyLength-len([]rune(footer))) + footer,
		Labels: labels,
		Key:    key,
	}, nil
}

// newKey derives a Key from the notification group and the identifiers of
// the finding. The identifiers are UUIDs or IDs assigned by Dependency-Track,
// so the same finding always yields the same key.
func newKey(group string, ids ...string) string {
	h := sha256.Sum256([]byte(strings.Join(append([]string{group}, ids...), "\x00")))
	return keyPrefix + hex.EncodeToString(h[:16])
}

// componentName returns a human-readable component string, e.g. "apache:axis 1.4"
func componentName(c notification.Component) string {
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
func projectName(p notification.Project) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}

func cvssScore(v notification.Vulnerability) string {
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

func aliasIDs(v notification.Vulnerability) string {
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

// neutralizeMentions inserts a zero-width space after such an "@" so that
// text coming from Dependency-Track cannot notify GitHub users or teams.
func neutralizeMentions(s string) string {
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
func inline(s string) string { return neutralizeMentions(inlineReplacer.Replace(s)) }

// block makes untrusted multi-line text safe for the issue body.
func block(s string) string { return neutralizeMentions(s) }

// truncate shortens s to at most limit characters, marking the cut with "…".
func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}
