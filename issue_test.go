package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInline(t *testing.T) {
	t.Parallel()
	got := inline("a|b\r\nc\nd @team")
	want := "a\\|b c d @\u200bteam"
	if got != want {
		t.Errorf("inline() = %q, want %q", got, want)
	}
}

func TestBlockNeutralizesMentionsOnly(t *testing.T) {
	t.Parallel()
	got := block("@admin line1\nping (@octocat) | pkg:npm/lodash@4.17.21 me@example.com")
	want := "@\u200badmin line1\nping (@\u200boctocat) | pkg:npm/lodash@4.17.21 me@example.com"
	if got != want {
		t.Errorf("block() = %q, want %q", got, want)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate() = %q, want unchanged", got)
	}
	got := truncate(strings.Repeat("é", 300), maxTitleLength)
	if n := utf8.RuneCountInString(got); n != maxTitleLength {
		t.Errorf("truncate() length = %d, want %d", n, maxTitleLength)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate() = %q, want ellipsis suffix", got)
	}
}

func TestNewIssueSanitizesAndTruncates(t *testing.T) {
	t.Parallel()
	issue := newIssue("[DT] @org/team\n"+strings.Repeat("x", 400), strings.Repeat("y", maxBodyLength+10), nil)
	if strings.Contains(issue.Title, "\n") || !strings.Contains(issue.Title, "@\u200borg") {
		t.Errorf("title not sanitized: %q", issue.Title)
	}
	if n := utf8.RuneCountInString(issue.Title); n > maxTitleLength {
		t.Errorf("title length = %d, want <= %d", n, maxTitleLength)
	}
	if n := utf8.RuneCountInString(issue.Body); n > maxBodyLength {
		t.Errorf("body length = %d, want <= %d", n, maxBodyLength)
	}
}

func TestCVSSScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v    vulnerability
		want string
	}{
		{vulnerability{CVSSv2: 5, CVSSv3: 6, CVSSv4: 7}, "7.0 (v4)"},
		{vulnerability{CVSSv2: 5, CVSSv3: 6.55}, "6.5 (v3)"},
		{vulnerability{CVSSv2: 5}, "5.0 (v2)"},
		{vulnerability{}, "N/A"},
	}
	for _, tc := range tests {
		if got := cvssScore(tc.v); got != tc.want {
			t.Errorf("cvssScore(%+v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

var update = flag.Bool("update", false, "update golden files in testdata/golden")

// TestIssueGolden renders the issue for each fixture and compares it with
// testdata/golden/<fixture>.md. Run `go test -run TestIssueGolden -update`
// after an intended format change and review the diff.
func TestIssueGolden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		build   func(notification) (gitHubIssueRequest, error)
	}{
		{"new_vulnerability", func(n notification) (gitHubIssueRequest, error) {
			s, err := decodeSubject[newVulnerabilitySubject](n)
			return buildNewVulnerabilityIssue(s), err
		}},
		{"new_vulnerable_dependency", func(n notification) (gitHubIssueRequest, error) {
			s, err := decodeSubject[newVulnerableDependencySubject](n)
			return buildNewVulnerableDependencyIssue(s), err
		}},
		{"policy_violation", func(n notification) (gitHubIssueRequest, error) {
			s, err := decodeSubject[policyViolationSubject](n)
			return buildPolicyViolationIssue(s), err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			n, err := parseNotification(readFixture(t, tc.fixture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			issue, err := tc.build(n)
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("# %s\n\nLabels: %s\n\n%s", issue.Title, strings.Join(issue.Labels, ", "), issue.Body)

			path := filepath.Join("testdata", "golden", tc.fixture+".md")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got != string(want) {
				t.Errorf("issue for %s differs from %s (run with -update and review the diff):\n%s", tc.fixture, path, got)
			}
		})
	}
}
