package issue

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/thomasvitale/dt-github-notifier/internal/notification"
	"github.com/thomasvitale/dt-github-notifier/internal/notification/notificationtest"
)

func TestPlainText(t *testing.T) {
	t.Parallel()
	got := plainText("a|b\r\nc  @team owner/repo#12 pkg:npm/a@1.0 C#")
	want := "a|b c @\u200bteam owner/repo#\u200b12 pkg:npm/a@1.0 C#"
	if got != want {
		t.Errorf("plainText() = %q, want %q", got, want)
	}
}

func TestCodeSpan(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"":                 "",
		"lodash 4.17.21":   "`lodash 4.17.21`",
		"a|b\nc":           "`a\\|b c`",
		"use `x`":          "`` use `x` ``",
		"`x`":              "`` `x` ``",
		"[link](http://x)": "`[link](http://x)`",
	}
	for in, want := range tests {
		if got := codeSpan(in); got != want {
			t.Errorf("codeSpan(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeBlock(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"line1\r\nline2\n": "```\nline1\nline2\n```",
		"x\n```\n@team":    "````\nx\n```\n@team\n````",
	}
	for in, want := range tests {
		if got := codeBlock(in); got != want {
			t.Errorf("codeBlock(%q) = %q, want %q", in, got, want)
		}
	}
	if n := utf8.RuneCountInString(codeBlock(strings.Repeat("x", maxTextLength*2))); n > maxTextLength+8 {
		t.Errorf("codeBlock() of a long text has %d characters, want at most %d", n, maxTextLength+8)
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

func TestIssueSanitizesAndTruncates(t *testing.T) {
	t.Parallel()
	issue, err := ForNewVulnerability(notification.NewVulnerabilitySubject{
		Component:     notification.Component{Name: "@org/team\n" + strings.Repeat("x", 400)},
		Vulnerability: notification.Vulnerability{VulnID: "CVE-1", Description: strings.Repeat("y", maxBodyLength+10)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(issue.Title, "\n") || !strings.Contains(issue.Title, "@\u200borg") {
		t.Errorf("title not sanitized: %q", issue.Title)
	}
	if n := utf8.RuneCountInString(issue.Title); n != maxTitleLength {
		t.Errorf("title length = %d, want %d", n, maxTitleLength)
	}
	if n := utf8.RuneCountInString(issue.Body); n > maxBodyLength {
		t.Errorf("body length = %d, want at most %d", n, maxBodyLength)
	}
	if !strings.Contains(issue.Body, "…\n```\n") {
		t.Error("long description is not truncated inside a closed code block")
	}
	if !strings.HasSuffix(issue.Body, "(deduplication key: `"+issue.Key+"`).\n") {
		t.Errorf("truncated body lost the footer with the key: ...%q", issue.Body[len(issue.Body)-200:])
	}
}

func TestKey(t *testing.T) {
	t.Parallel()
	vuln := func(project, component, vulnID string) string {
		i, err := ForNewVulnerability(notification.NewVulnerabilitySubject{
			Project:       notification.Project{UUID: project},
			Component:     notification.Component{UUID: component},
			Vulnerability: notification.Vulnerability{Source: "NVD", VulnID: vulnID, Description: "changes over time"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return i.Key
	}

	k := vuln("p1", "c1", "CVE-1")
	if !strings.HasPrefix(k, keyPrefix) || len(k) != len(keyPrefix)+32 {
		t.Errorf("key %q, want %s followed by 32 hex characters", k, keyPrefix)
	}
	if k != vuln("p1", "c1", "CVE-1") {
		t.Error("the same finding yields different keys")
	}
	for name, other := range map[string]string{
		"other project":       vuln("p2", "c1", "CVE-1"),
		"other component":     vuln("p1", "c2", "CVE-1"),
		"other vulnerability": vuln("p1", "c1", "CVE-2"),
		"other group":         newKey("other-group", "p1", "c1", "NVD", "CVE-1"),
	} {
		if other == k {
			t.Errorf("%s yields the same key", name)
		}
	}
}

func TestCVSSScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		v    notification.Vulnerability
		want string
	}{
		{notification.Vulnerability{CVSSv2: 5, CVSSv3: 6, CVSSv4: 7}, "7.0 (v4)"},
		{notification.Vulnerability{CVSSv2: 5, CVSSv3: 6.55}, "6.5 (v3)"},
		{notification.Vulnerability{CVSSv2: 5}, "5.0 (v2)"},
		{notification.Vulnerability{}, "N/A"},
	}
	for _, tc := range tests {
		if got := cvssScore(tc.v); got != tc.want {
			t.Errorf("cvssScore(%+v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

var update = flag.Bool("update", false, "update golden files in testdata/golden")

// TestIssueGolden renders the issue for each fixture and compares it with
// testdata/golden/<fixture>.md. Run `go test -run TestGolden -update`
// after an intended format change and review the diff.
func TestGolden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		build   func(notification.Notification) (Issue, error)
	}{
		{notificationtest.NewVulnerability, func(n notification.Notification) (Issue, error) {
			s, err := notification.DecodeSubject[notification.NewVulnerabilitySubject](n)
			if err != nil {
				return Issue{}, err
			}
			return ForNewVulnerability(s)
		}},
		{notificationtest.PolicyViolation, func(n notification.Notification) (Issue, error) {
			s, err := notification.DecodeSubject[notification.PolicyViolationSubject](n)
			if err != nil {
				return Issue{}, err
			}
			return ForPolicyViolation(s)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			n, err := notification.Parse(notificationtest.Payload(t, tc.fixture))
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

func FuzzPlainText(f *testing.F) {
	for _, s := range []string{"a\r\nb", "@team", "(@a(@b", "@@a", "pkg:npm/a@1.0", "x#1 #2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := plainText(s)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("plainText(%q) = %q contains a line break", s, got)
		}
		if mentionPattern.MatchString(got) || referencePattern.MatchString(got) {
			t.Errorf("plainText(%q) = %q still contains a mention or reference", s, got)
		}
	})
}

// The text must not be able to end the code span or block it is rendered in.

func FuzzCodeSpan(f *testing.F) {
	for _, s := range []string{"a|b\r\nc", "`", "``x``", " ` ", "a\\|b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := codeSpan(s)
		if got == "" {
			return
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("codeSpan(%q) = %q contains a line break", s, got)
		}
		delim := strings.Repeat("`", longestRun(got, '`'))
		inner := strings.TrimSuffix(strings.TrimPrefix(got, delim), delim)
		if longestRun(inner, '`') >= len(delim) {
			t.Errorf("codeSpan(%q) = %q: content can close the span", s, got)
		}
		if strings.Contains(strings.ReplaceAll(inner, "\\|", ""), "|") {
			t.Errorf("codeSpan(%q) = %q contains an unescaped |", s, got)
		}
	})
}

func FuzzCodeBlock(f *testing.F) {
	for _, s := range []string{"x", "```", "a\n````\nb", "~~~"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := codeBlock(s)
		first, rest, _ := strings.Cut(got, "\n")
		inner, _ := strings.CutSuffix(rest, "\n"+first)
		if strings.Trim(first, "`") != "" || len(first) < 3 || !strings.HasSuffix(got, "\n"+first) {
			t.Fatalf("codeBlock(%q) = %q is not fenced", s, got)
		}
		if longestRun(inner, '`') >= len(first) {
			t.Errorf("codeBlock(%q) = %q: content can close the fence", s, got)
		}
	})
}

// TestOptionalSectionsOmitted checks the template whitespace handling when
// optional sections (aliases, description, message) are empty.
func TestOptionalSectionsOmitted(t *testing.T) {
	t.Parallel()
	footer := func(i Issue) string {
		return "\n> This issue was created automatically by dt-github-notifier (deduplication key: `" + i.Key + "`).\n"
	}

	vuln, err := ForNewVulnerability(notification.NewVulnerabilitySubject{
		Component:     notification.Component{Name: "c"},
		Project:       notification.Project{Name: "p"},
		Vulnerability: notification.Vulnerability{VulnID: "CVE-1", Source: "NVD", Severity: "LOW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantVuln := "## :shield: New Vulnerability Identified\n\n" +
		"| Field | Value |\n|---|---|\n" +
		"| **CVE / ID** | `CVE-1` |\n" +
		"| **Source** | `NVD` |\n" +
		"| **Severity** | `LOW` |\n" +
		"| **CVSS Score** | `N/A` |\n" +
		"| **Project** | `p` |\n" +
		"| **Component** | `c` |\n" + footer(vuln)
	if vuln.Body != wantVuln {
		t.Errorf("new vulnerability body =\n%q\nwant\n%q", vuln.Body, wantVuln)
	}

	pv, err := ForPolicyViolation(notification.PolicyViolationSubject{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pv.Body, "**Message:**") || !strings.HasSuffix(pv.Body, "| **Timestamp** |  |\n"+footer(pv)) {
		t.Errorf("policy violation body without message =\n%q", pv.Body)
	}
}
