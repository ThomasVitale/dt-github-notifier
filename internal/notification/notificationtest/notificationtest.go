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
