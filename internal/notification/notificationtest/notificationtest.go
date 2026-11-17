// Package notificationtest provides Dependency-Track v5 webhook payloads for
// tests, taken from the publisher tests of Dependency-Track itself.
package notificationtest

import (
	"embed"
	"testing"
)

// Payload names, matching the files in payloads/.
const (
	BOMConsumed             = "bom_consumed"
	NewVulnerability        = "new_vulnerability"
	NewVulnerableDependency = "new_vulnerable_dependency"
	PolicyViolation         = "policy_violation"
	// Audit decisions and a retraction about the findings of the payloads
	// above, built like the notifications of Dependency-Track's
	// TestNotificationFactory: FALSE_POSITIVE and REJECTED, both suppressed.
	ProjectAuditChangeVulnerability   = "project_audit_change_vulnerability"
	ProjectAuditChangePolicyViolation = "project_audit_change_policy_violation"
	VulnerabilityRetracted            = "vulnerability_retracted"
)

//go:embed payloads/*.json
var payloads embed.FS

// Payload returns the raw request body of the named payload.
func Payload(tb testing.TB, name string) []byte {
	tb.Helper()
	b, err := payloads.ReadFile("payloads/" + name + ".json")
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
