// Package notification decodes the notifications sent by the Dependency-Track
// v5 webhook publisher with its default template. The envelope is rendered by
// the template, while the subject is the Protobuf JSON encoding of the group's
// subject message.
// https://dependencytrack.github.io/docs/next/reference/notifications/schema/
package notification

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	GroupNewVulnerability        = "GROUP_NEW_VULNERABILITY"
	GroupNewVulnerableDependency = "GROUP_NEW_VULNERABLE_DEPENDENCY"
	GroupPolicyViolation         = "GROUP_POLICY_VIOLATION"
)

type Notification struct {
	ID        string          `json:"id"`
	Level     string          `json:"level"`
	Scope     string          `json:"scope"`
	Group     string          `json:"group"`
	Timestamp string          `json:"timestamp"`
	Title     string          `json:"title"`
	Content   string          `json:"content"`
	Subject   json.RawMessage `json:"subject"`
}

type Project struct {
	UUID    string   `json:"uuid"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	PURL    string   `json:"purl"`
	Tags    []string `json:"tags"`
}

type Component struct {
	UUID    string `json:"uuid"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type Vulnerability struct {
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

type PolicyViolation struct {
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

type NewVulnerabilitySubject struct {
	Component     Component     `json:"component"`
	Project       Project       `json:"project"`
	Vulnerability Vulnerability `json:"vulnerability"`
}

type NewVulnerableDependencySubject struct {
	Component       Component       `json:"component"`
	Project         Project         `json:"project"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type PolicyViolationSubject struct {
	Component       Component       `json:"component"`
	Project         Project         `json:"project"`
	PolicyViolation PolicyViolation `json:"policyViolation"`
}

// ErrInvalidPayload wraps every error caused by a malformed notification.
var ErrInvalidPayload = errors.New("invalid notification payload")

// Parse decodes the notification envelope. The subject is left raw, to be
// decoded by DecodeSubject once the group is known to be handled.
func Parse(body []byte) (Notification, error) {
	var envelope struct {
		Notification *Notification `json:"notification"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Notification{}, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	if envelope.Notification == nil || envelope.Notification.Group == "" {
		return Notification{}, fmt.Errorf("%w: missing notification group", ErrInvalidPayload)
	}
	return *envelope.Notification, nil
}

// Subject is the set of subject types of the handled notification groups.
type Subject interface {
	NewVulnerabilitySubject | NewVulnerableDependencySubject | PolicyViolationSubject
}

// DecodeSubject decodes the subject of n into the subject type T.
func DecodeSubject[T Subject](n Notification) (T, error) {
	var s T
	if len(n.Subject) == 0 || string(n.Subject) == "null" {
		return s, fmt.Errorf("%w: %s notification has no subject", ErrInvalidPayload, n.Group)
	}
	if err := json.Unmarshal(n.Subject, &s); err != nil {
		return s, fmt.Errorf("%w: %s subject: %w", ErrInvalidPayload, n.Group, err)
	}
	return s, nil
}
