package issue

import (
	"slices"

	"github.com/thomasvitale/dt-github-notifier/internal/notification"
)

// Reasons for closing an issue, as GitHub's state_reason.
const (
	ReasonCompleted  = "completed"
	ReasonNotPlanned = "not_planned"
)

// Closure closes the open issue about a finding that no longer needs action.
type Closure struct {
	// Key identifies the issue, as Issue.Key.
	Key string
	// Comment explains why the issue is closed.
	Comment string
	// Reason is ReasonCompleted or ReasonNotPlanned.
	Reason string
}

// resolvingStates are the vulnerability analysis states meaning that no
// action is needed.
var resolvingStates = []string{"FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED"}

// ForProjectAuditChange returns the Closure for an audit decision that
// resolves a vulnerability or policy violation, and false when the decision
// leaves it open (e.g. IN_TRIAGE, EXPLOITABLE or REJECTED).
func ForProjectAuditChange(s notification.ProjectAuditChangeSubject) (Closure, bool) {
	a := s.Analysis
	switch {
	case s.Vulnerability != nil:
		if !a.Suppressed && !slices.Contains(resolvingStates, a.State) {
			return Closure{}, false
		}
		reason := ReasonNotPlanned
		if a.State == "RESOLVED" {
			reason = ReasonCompleted
		}
		return Closure{
			Key:     VulnerabilityKey(s.Project, s.Component, *s.Vulnerability),
			Comment: auditComment("vulnerability", a),
			Reason:  reason,
		}, true
	case s.PolicyViolation != nil:
		if !a.Suppressed && a.State != "APPROVED" {
			return Closure{}, false
		}
		return Closure{
			Key:     PolicyViolationKey(s.Project, s.Component, *s.PolicyViolation),
			Comment: auditComment("policy violation", a),
			Reason:  ReasonNotPlanned,
		}, true
	default:
		return Closure{}, false
	}
}

// ForVulnerabilityRetracted returns the Closure for a vulnerability report
// that Dependency-Track retracted.
func ForVulnerabilityRetracted(s notification.VulnerabilityRetractedSubject) Closure {
	return Closure{
		Key: VulnerabilityKey(s.Project, s.Component, s.Vulnerability),
		Comment: "Closed automatically by dt-github-notifier: Dependency-Track retracted this " +
			"vulnerability report, which no longer applies to the component.",
		Reason: ReasonNotPlanned,
	}
}

func auditComment(finding string, a notification.Analysis) string {
	comment := "Closed automatically by dt-github-notifier: in Dependency-Track, the analysis of this " + finding
	switch {
	case a.State != "" && a.State != "NOT_SET" && a.Suppressed:
		comment += " is " + codeSpan(a.State) + " and the " + finding + " is suppressed."
	case a.Suppressed:
		comment += " suppressed the " + finding + "."
	default:
		comment += " is " + codeSpan(a.State) + "."
	}
	return comment
}
