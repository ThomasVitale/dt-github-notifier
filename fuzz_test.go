package main

import (
	"strings"
	"testing"
)

// Every repo extracted from untrusted DT data must be a valid "owner/repo",
// as it ends up in the GitHub API request path.

func FuzzRepoFromURL(f *testing.F) {
	for _, s := range []string{
		"https://github.com/myorg/myrepo",
		"https://github.com/myorg/myrepo.git",
		"https://github.com/myorg/myrepo/tree/main",
		"https://github.com/myorg/..",
		"git@github.com:myorg/myrepo.git",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if repo, ok := repoFromURL(s); ok && !isValidRepo(repo) {
			t.Errorf("repoFromURL(%q) = %q, which is not a valid repo", s, repo)
		}
	})
}

func FuzzRepoFromPURL(f *testing.F) {
	for _, s := range []string{
		"pkg:github/myorg/myrepo@1.0.0",
		"pkg:github/myorg/myrepo?arch=amd64#sub",
		"pkg:github/myorg/..",
		"pkg:maven/org.apache/commons@1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if repo, ok := repoFromPURL(s); ok && !isValidRepo(repo) {
			t.Errorf("repoFromPURL(%q) = %q, which is not a valid repo", s, repo)
		}
	})
}

func FuzzInline(f *testing.F) {
	for _, s := range []string{"a|b\r\nc", "@team", "(@a(@b", "@@a", "pkg:npm/a@1.0", "x @a @b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := inline(s)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("inline(%q) = %q contains a line break", s, got)
		}
		if strings.Contains(strings.ReplaceAll(got, "\\|", ""), "|") {
			t.Errorf("inline(%q) = %q contains an unescaped |", s, got)
		}
		if mentionPattern.MatchString(got) {
			t.Errorf("inline(%q) = %q still contains a mention", s, got)
		}
	})
}

func FuzzParseNotification(f *testing.F) {
	f.Add([]byte(`{"notification":{"group":"GROUP_POLICY_VIOLATION","subject":{"project":{"uuid":"x"}}}}`))
	f.Add([]byte(`{"notification":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		n, err := parseNotification(body)
		if err != nil {
			return
		}
		// Decoding any subject must not panic.
		_, _ = decodeSubject[policyViolationSubject](n)
		_, _ = decodeSubject[newVulnerabilitySubject](n)
		_, _ = decodeSubject[newVulnerableDependencySubject](n)
	})
}
