package main

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestIsValidRepo(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"myorg/myrepo":          true,
		"my-org/my.repo_name-2": true,
		"myorg":                 false,
		"myorg/":                false,
		"/myrepo":               false,
		"myorg/myrepo/extra":    false,
		"myorg/..":              false,
		"myorg/.":               false,
		"../../orgs/evil":       false,
		"-org/repo":             false,
		"my_org/repo":           false,
		"myorg/repo?x=1":        false,
		"myorg/repo name":       false,
	}
	for repo, want := range tests {
		if got := isValidRepo(repo); got != want {
			t.Errorf("isValidRepo(%q) = %v, want %v", repo, got, want)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	tests := []struct {
		name    string
		headers map[string]string
		want    time.Duration
	}{
		{"none", nil, 0},
		{"retry-after seconds", map[string]string{"Retry-After": "30"}, 30 * time.Second},
		{"invalid retry-after", map[string]string{"Retry-After": "soon"}, 0},
		{
			"rate limit reset",
			map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": strconv.FormatInt(now.Unix()+90, 10)},
			90 * time.Second,
		},
		{
			"reset ignored while requests remain",
			map[string]string{"X-Ratelimit-Remaining": "10", "X-Ratelimit-Reset": strconv.FormatInt(now.Unix()+90, 10)},
			0,
		},
	}
	for _, tc := range tests {
		h := http.Header{}
		for k, v := range tc.headers {
			h.Set(k, v)
		}
		if got := retryAfter(h, now); got != tc.want {
			t.Errorf("%s: retryAfter() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
