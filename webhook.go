package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/DependencyTrack/client-go/notification"
)

type webhookHandler struct {
	gh       *gitHubClient
	resolver *repoResolver
}

func newWebhookHandler(gh *gitHubClient, resolver *repoResolver) *webhookHandler {
	return &webhookHandler{gh: gh, resolver: resolver}
}

// issueTarget pairs a resolved GitHub repo with the issue to create in it.
type issueTarget struct {
	repo  string
	issue gitHubIssueRequest
}

// projectEntry holds the name and version of an affected project.
type projectEntry struct {
	name    string
	version string
}

func (h *webhookHandler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	n, err := notification.Parse(r.Body)
	if err != nil {
		slog.Error("failed to parse notification body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	slog.Info("received notification", "group", n.Group, "level", n.Level, "title", n.Title)

	targets, err := h.buildTargets(r.Context(), n)
	if err != nil {
		// Notification group we don't handle — acknowledge silently.
		slog.Info("skipping unhandled notification", "group", n.Group)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Create all issues, logging individual failures but not aborting early.
	// A partial success is still a success from DT's perspective — we must
	// return 2xx so DT does not keep retrying the whole notification.
	var firstErr error
	for _, t := range targets {
		if err := h.gh.createIssue(r.Context(), t.repo, t.issue); err != nil {
			slog.Error("failed to create GitHub issue",
				"err", err, "repo", t.repo, "title", t.issue.Title)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		slog.Info("created GitHub issue", "repo", t.repo, "title", t.issue.Title)
	}

	if firstErr != nil && len(targets) == 1 {
		// Only surface a 500 when every single target failed (i.e. there was
		// just one and it failed). For fan-out with partial success, return 204.
		http.Error(w, "failed to create issue", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// buildTargets resolves repos and builds issues for every project affected by
// the notification. For most groups this is a single target; for
// NEW_VULNERABILITY it produces one target per affected project so each repo
// gets its own issue.
func (h *webhookHandler) buildTargets(ctx context.Context, n notification.Notification) ([]issueTarget, error) {
	switch subject := n.Subject.(type) {

	case *notification.PolicyViolationSubject:
		repo, err := h.resolver.Resolve(ctx, subject.Project.UUID)
		if err != nil {
			return nil, err
		}
		return []issueTarget{{repo: repo, issue: buildPolicyViolationIssue(subject)}}, nil

	case *notification.NewVulnerabilitySubject:
		if len(subject.AffectedProjects) == 0 {
			return nil, fmt.Errorf("NEW_VULNERABILITY notification has no affected projects")
		}
		return h.fanOutVulnerability(ctx, subject)

	case *notification.NewVulnerableDependencySubject:
		repo, err := h.resolver.Resolve(ctx, subject.Project.UUID)
		if err != nil {
			return nil, err
		}
		return []issueTarget{{repo: repo, issue: buildNewVulnerableDependencyIssue(subject)}}, nil

	default:
		return nil, fmt.Errorf("unhandled notification group %q", n.Group)
	}
}

// fanOutVulnerability creates one issueTarget per affected project, deduplicating
// by repo so that projects sharing a repo produce only a single issue listing
// all of them rather than N identical issues.
func (h *webhookHandler) fanOutVulnerability(ctx context.Context, s *notification.NewVulnerabilitySubject) ([]issueTarget, error) {
	// Map repo → list of project names, to deduplicate.
	repoProjects := make(map[string][]projectEntry)
	repoOrder := make([]string, 0) // preserve stable order

	for _, p := range s.AffectedProjects {
		repo, err := h.resolver.Resolve(ctx, p.UUID)
		if err != nil {
			slog.Warn("could not resolve repo for affected project, skipping",
				"project", p.Name, "err", err)
			continue
		}
		if _, seen := repoProjects[repo]; !seen {
			repoOrder = append(repoOrder, repo)
		}
		repoProjects[repo] = append(repoProjects[repo], projectEntry{p.Name, p.Version})
	}

	if len(repoOrder) == 0 {
		return nil, fmt.Errorf("could not resolve any repos for NEW_VULNERABILITY notification")
	}

	targets := make([]issueTarget, 0, len(repoOrder))
	for _, repo := range repoOrder {
		projects := repoProjects[repo]
		targets = append(targets, issueTarget{
			repo:  repo,
			issue: buildNewVulnerabilityIssue(s, projects),
		})
	}
	return targets, nil
}

// ── Issue builders ────────────────────────────────────────────────────────────

func buildPolicyViolationIssue(s *notification.PolicyViolationSubject) gitHubIssueRequest {
	policy := s.PolicyViolation.PolicyCondition.Policy

	title := fmt.Sprintf("[DT] Policy Violation: %s in %s %s",
		policy.Name, s.Project.Name, s.Project.Version)

	body := fmt.Sprintf("## :rotating_light: Policy Violation Detected\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| **Project** | %s %s |\n"+
		"| **Component** | %s |\n"+
		"| **Policy** | %s |\n"+
		"| **Violation State** | %s |\n"+
		"| **Type** | %s |\n"+
		"| **Condition** | %s %s `%s` |\n"+
		"| **Timestamp** | %s |\n\n"+
		"> This issue was created automatically by dt-github-notifier.\n",
		s.Project.Name, s.Project.Version,
		componentName(s.Component),
		policy.Name,
		policy.ViolationState,
		s.PolicyViolation.Type,
		s.PolicyViolation.PolicyCondition.Subject,
		s.PolicyViolation.PolicyCondition.Operator,
		s.PolicyViolation.PolicyCondition.Value,
		s.PolicyViolation.Timestamp,
	)

	return gitHubIssueRequest{
		Title: title,
		Body:  body,
		Labels: []string{
			"security",
			"policy-violation",
			"dependency-track",
			"violation-state:" + strings.ToLower(string(policy.ViolationState)),
		},
	}
}

// buildNewVulnerabilityIssue builds an issue for one repo, listing only the
// projects that belong to that repo (already filtered by the caller).
func buildNewVulnerabilityIssue(s *notification.NewVulnerabilitySubject, projects []projectEntry) gitHubIssueRequest {
	v := s.Vulnerability

	title := fmt.Sprintf("[DT] %s (%s) in %s", v.VulnID, v.Severity, componentName(s.Component))

	var projectLines strings.Builder
	for _, p := range projects {
		fmt.Fprintf(&projectLines, "- %s %s\n", p.name, p.version)
	}

	cvss := "N/A"
	if v.CVSSV3 > 0 {
		cvss = fmt.Sprintf("%.1f (v3)", v.CVSSV3)
	} else if v.CVSSV2 > 0 {
		cvss = fmt.Sprintf("%.1f (v2)", v.CVSSV2)
	}

	body := fmt.Sprintf("## :shield: New Vulnerability Identified\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| **CVE / ID** | %s |\n"+
		"| **Source** | %s |\n"+
		"| **Severity** | %s |\n"+
		"| **CVSS Score** | %s |\n"+
		"| **Component** | %s |\n\n"+
		"**Affected Projects:**\n%s\n"+
		"**Description:**\n%s\n\n"+
		"> This issue was created automatically by dt-github-notifier.\n",
		v.VulnID, v.Source, v.Severity, cvss,
		componentName(s.Component),
		projectLines.String(),
		v.Description,
	)

	return gitHubIssueRequest{
		Title: title,
		Body:  body,
		Labels: []string{
			"security",
			"vulnerability",
			"dependency-track",
			"severity:" + strings.ToLower(v.Severity),
		},
	}
}

func buildNewVulnerableDependencyIssue(s *notification.NewVulnerableDependencySubject) gitHubIssueRequest {
	title := fmt.Sprintf("[DT] Vulnerable Dependency: %s introduced in %s %s",
		componentName(s.Component), s.Project.Name, s.Project.Version)

	var vulnLines strings.Builder
	for _, v := range s.Vulnerabilities {
		fmt.Fprintf(&vulnLines, "- **%s** (%s) — %s\n", v.VulnID, v.Severity, v.Source)
	}

	body := fmt.Sprintf("## :warning: Vulnerable Dependency Introduced\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| **Project** | %s %s |\n"+
		"| **Component** | %s |\n\n"+
		"**Vulnerabilities:**\n%s\n"+
		"> This issue was created automatically by dt-github-notifier.\n",
		s.Project.Name, s.Project.Version,
		componentName(s.Component),
		vulnLines.String(),
	)

	return gitHubIssueRequest{
		Title:  title,
		Body:   body,
		Labels: []string{"security", "vulnerable-dependency", "dependency-track"},
	}
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
