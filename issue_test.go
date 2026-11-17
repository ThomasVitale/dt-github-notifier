package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInline(t *testing.T) {
	t.Parallel()
	got := inline("a|b\r\nc\nd @team")
	want := "a\\|b c d @​team"
	if got != want {
		t.Errorf("inline() = %q, want %q", got, want)
	}
}

func TestBlockNeutralisesMentionsOnly(t *testing.T) {
	t.Parallel()
	got := block("line1\nping @octocat | done")
	want := "line1\nping @​octocat | done"
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

func TestNewIssueSanitisesAndTruncates(t *testing.T) {
	t.Parallel()
	issue := newIssue("[DT] @org/team\n"+strings.Repeat("x", 400), strings.Repeat("y", maxBodyLength+10), nil)
	if strings.Contains(issue.Title, "\n") || !strings.Contains(issue.Title, "@​org") {
		t.Errorf("title not sanitised: %q", issue.Title)
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
