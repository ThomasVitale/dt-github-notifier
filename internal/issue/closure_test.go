package issue

import (
	"strings"
	"testing"

	"github.com/thomasvitale/dt-github-notifier/internal/notification"
)

func TestForProjectAuditChange(t *testing.T) {
	t.Parallel()
	project := notification.Project{UUID: "p"}
	component := notification.Component{UUID: "c"}
	vuln := &notification.Vulnerability{Source: "NVD", VulnID: "CVE-1"}
	violation := &notification.PolicyViolation{}
	violation.Condition.UUID = "cond"

	tests := []struct {
		name        string
		subject     notification.ProjectAuditChangeSubject
		wantClose   bool
		wantKey     string
		wantReason  string
		wantComment string
	}{
		{
			name:        "vulnerability resolved",
			subject:     notification.ProjectAuditChangeSubject{Vulnerability: vuln, Analysis: notification.Analysis{State: "RESOLVED"}},
			wantClose:   true,
			wantKey:     VulnerabilityKey(project, component, *vuln),
			wantReason:  ReasonCompleted,
			wantComment: "analysis of this vulnerability is `RESOLVED`.",
		},
		{
			name:        "vulnerability not affected",
			subject:     notification.ProjectAuditChangeSubject{Vulnerability: vuln, Analysis: notification.Analysis{State: "NOT_AFFECTED"}},
			wantClose:   true,
			wantKey:     VulnerabilityKey(project, component, *vuln),
			wantReason:  ReasonNotPlanned,
			wantComment: "`NOT_AFFECTED`",
		},
		{
			name:        "vulnerability suppressed without state",
			subject:     notification.ProjectAuditChangeSubject{Vulnerability: vuln, Analysis: notification.Analysis{State: "NOT_SET", Suppressed: true}},
			wantClose:   true,
			wantKey:     VulnerabilityKey(project, component, *vuln),
			wantReason:  ReasonNotPlanned,
			wantComment: "suppressed the vulnerability.",
		},
		{
			name:    "vulnerability exploitable",
			subject: notification.ProjectAuditChangeSubject{Vulnerability: vuln, Analysis: notification.Analysis{State: "EXPLOITABLE"}},
		},
		{
			name:    "vulnerability in triage",
			subject: notification.ProjectAuditChangeSubject{Vulnerability: vuln, Analysis: notification.Analysis{State: "IN_TRIAGE"}},
		},
		{
			name:        "policy violation approved",
			subject:     notification.ProjectAuditChangeSubject{PolicyViolation: violation, Analysis: notification.Analysis{State: "APPROVED"}},
			wantClose:   true,
			wantKey:     PolicyViolationKey(project, component, *violation),
			wantReason:  ReasonNotPlanned,
			wantComment: "policy violation is `APPROVED`.",
		},
		{
			name:    "policy violation rejected",
			subject: notification.ProjectAuditChangeSubject{PolicyViolation: violation, Analysis: notification.Analysis{State: "REJECTED"}},
		},
		{
			name:    "neither vulnerability nor policy violation",
			subject: notification.ProjectAuditChangeSubject{Analysis: notification.Analysis{Suppressed: true}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.subject.Project, tc.subject.Component = project, component
			c, ok := ForProjectAuditChange(tc.subject)
			if ok != tc.wantClose {
				t.Fatalf("ForProjectAuditChange() closes = %v, want %v", ok, tc.wantClose)
			}
			if !ok {
				return
			}
			if c.Key != tc.wantKey || c.Reason != tc.wantReason || !strings.Contains(c.Comment, tc.wantComment) {
				t.Errorf("ForProjectAuditChange() = %+v, want key %q, reason %q, comment containing %q",
					c, tc.wantKey, tc.wantReason, tc.wantComment)
			}
		})
	}
}

func TestClosureCommentIsSafe(t *testing.T) {
	t.Parallel()
	c, ok := ForProjectAuditChange(notification.ProjectAuditChangeSubject{
		Vulnerability: &notification.Vulnerability{},
		Analysis:      notification.Analysis{State: "RESOLVED", Suppressed: true},
	})
	if !ok {
		t.Fatal("not closed")
	}
	// Even the state, an enumeration from DT, is rendered as code.
	if !strings.Contains(c.Comment, "`RESOLVED`") {
		t.Errorf("comment %q does not render the state as code", c.Comment)
	}
}
