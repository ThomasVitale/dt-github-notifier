package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Notification payloads as sent by the Dependency-Track v5 webhook publisher
// with its default template. The envelope is rendered by the template, while
// the subject is the Protobuf JSON encoding of the group's subject message.
// https://dependencytrack.github.io/docs/next/reference/notifications/schema/

const (
	groupNewVulnerability        = "GROUP_NEW_VULNERABILITY"
	groupNewVulnerableDependency = "GROUP_NEW_VULNERABLE_DEPENDENCY"
	groupPolicyViolation         = "GROUP_POLICY_VIOLATION"
)

type notification struct {
	ID        string          `json:"id"`
	Level     string          `json:"level"`
	Scope     string          `json:"scope"`
	Group     string          `json:"group"`
	Timestamp string          `json:"timestamp"`
	Title     string          `json:"title"`
	Content   string          `json:"content"`
	Subject   json.RawMessage `json:"subject"`
}

type project struct {
	UUID    string   `json:"uuid"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	PURL    string   `json:"purl"`
	Tags    []string `json:"tags"`
}

type component struct {
	UUID    string `json:"uuid"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type vulnerability struct {
	UUID    string `json:"uuid"`
	VulnID  string `json:"vulnId"`
	Source  string `json:"source"`
	Aliases []struct {
		VulnID string `json:"vulnId"`
		Source string `json:"source"`
	} `json:"aliases"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Recommendation string  `json:"recommendation"`
	Severity       string  `json:"severity"`
	CVSSv2         float64 `json:"cvssv2"`
	CVSSv3         float64 `json:"cvssv3"`
	CVSSv4         float64 `json:"cvssv4"`
}

type policyViolation struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Condition struct {
		Subject  string `json:"subject"`
		Operator string `json:"operator"`
		Value    string `json:"value"`
		Policy   struct {
			Name           string `json:"name"`
			ViolationState string `json:"violationState"`
		} `json:"policy"`
	} `json:"condition"`
}

type newVulnerabilitySubject struct {
	Component     component     `json:"component"`
	Project       project       `json:"project"`
	Vulnerability vulnerability `json:"vulnerability"`
}

type newVulnerableDependencySubject struct {
	Component       component       `json:"component"`
	Project         project         `json:"project"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type policyViolationSubject struct {
	Component       component       `json:"component"`
	Project         project         `json:"project"`
	PolicyViolation policyViolation `json:"policyViolation"`
}

// errInvalidPayload wraps every error caused by a malformed notification.
var errInvalidPayload = errors.New("invalid notification payload")

// parseNotification decodes the notification envelope. The subject is left
// raw, to be decoded by decodeSubject once the group is known to be handled.
func parseNotification(body []byte) (notification, error) {
	var envelope struct {
		Notification *notification `json:"notification"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return notification{}, fmt.Errorf("%w: %w", errInvalidPayload, err)
	}
	if envelope.Notification == nil || envelope.Notification.Group == "" {
		return notification{}, fmt.Errorf("%w: missing notification group", errInvalidPayload)
	}
	return *envelope.Notification, nil
}

// decodeSubject decodes the subject of n into the subject type T.
func decodeSubject[T newVulnerabilitySubject | newVulnerableDependencySubject | policyViolationSubject](n notification) (T, error) {
	var s T
	if len(n.Subject) == 0 || string(n.Subject) == "null" {
		return s, fmt.Errorf("%w: %s notification has no subject", errInvalidPayload, n.Group)
	}
	if err := json.Unmarshal(n.Subject, &s); err != nil {
		return s, fmt.Errorf("%w: %s subject: %w", errInvalidPayload, n.Group, err)
	}
	return s, nil
}
