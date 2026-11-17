package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/thomasvitale/dt-github-notifier/internal/issue"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
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
		if got := IsValidRepo(repo); got != want {
			t.Errorf("IsValidRepo(%q) = %v, want %v", repo, got, want)
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

func TestCreateIssue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		repo       string
		status     int
		headers    map[string]string
		message    string
		wantErr    bool
		wantRetry  bool
		wantAfter  time.Duration
		wantCalled bool
	}{
		{name: "created", repo: "myorg/myrepo", status: http.StatusCreated, wantCalled: true},
		{name: "invalid repo is rejected before calling GitHub", repo: "../evil", wantErr: true},
		{
			name: "secondary rate limit with Retry-After", repo: "myorg/myrepo",
			status: http.StatusForbidden, headers: map[string]string{"Retry-After": "60"},
			wantErr: true, wantRetry: true, wantAfter: time.Minute, wantCalled: true,
		},
		{
			name: "rate limit by message", repo: "myorg/myrepo",
			status: http.StatusForbidden, message: "You have exceeded a secondary rate limit",
			wantErr: true, wantRetry: true, wantCalled: true,
		},
		{
			name: "too many requests", repo: "myorg/myrepo",
			status:  http.StatusTooManyRequests,
			wantErr: true, wantRetry: true, wantCalled: true,
		},
		{
			name: "server error", repo: "myorg/myrepo",
			status:  http.StatusBadGateway,
			wantErr: true, wantRetry: true, wantCalled: true,
		},
		{
			name: "forbidden without rate limit is permanent", repo: "myorg/myrepo",
			status: http.StatusForbidden, message: "Resource not accessible by personal access token",
			wantErr: true, wantCalled: true,
		},
		{
			name: "unknown repo is permanent", repo: "myorg/myrepo",
			status:  http.StatusNotFound,
			wantErr: true, wantCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got struct {
				called bool
				path   string
				auth   string
				body   issueRequest
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.called, got.path, got.auth = true, r.URL.Path, r.Header.Get("Authorization")
				_ = json.NewDecoder(r.Body).Decode(&got.body)
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": tc.message, "html_url": "https://github.com/myorg/myrepo/issues/1"})
			}))
			defer srv.Close()

			c := New(srv.URL+"/", "test-token")
			url, err := c.CreateIssue(t.Context(), tc.repo, issue.Issue{Title: "t", Body: "b", Labels: []string{"l"}})

			if (err != nil) != tc.wantErr {
				t.Fatalf("CreateIssue() error = %v, wantErr %v", err, tc.wantErr)
			}
			after, retry := retryable.As(err)
			if retry != tc.wantRetry || after != tc.wantAfter {
				t.Errorf("CreateIssue() retryable = %v after %v, want %v after %v", retry, after, tc.wantRetry, tc.wantAfter)
			}
			if got.called != tc.wantCalled {
				t.Fatalf("GitHub called = %v, want %v", got.called, tc.wantCalled)
			}
			if !got.called {
				return
			}
			if got.path != "/repos/myorg/myrepo/issues" || got.auth != "Bearer test-token" {
				t.Errorf("request path = %q, Authorization = %q", got.path, got.auth)
			}
			if got.body.Title != "t" || got.body.Body != "b" || len(got.body.Labels) != 1 {
				t.Errorf("request body = %+v", got.body)
			}
			if !tc.wantErr && url != "https://github.com/myorg/myrepo/issues/1" {
				t.Errorf("CreateIssue() URL = %q", url)
			}
		})
	}
}

func TestFindOpenIssue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    int
		response  string
		headers   map[string]string
		want      string
		wantErr   bool
		wantRetry bool
	}{
		{
			name:     "found",
			status:   http.StatusOK,
			response: `{"total_count":1,"items":[{"html_url":"https://github.com/myorg/myrepo/issues/7"}]}`,
			want:     "https://github.com/myorg/myrepo/issues/7",
		},
		{
			name:     "not found",
			status:   http.StatusOK,
			response: `{"total_count":0,"items":[]}`,
		},
		{
			name:      "search rate limit is retryable",
			status:    http.StatusForbidden,
			response:  `{"message":"API rate limit exceeded"}`,
			headers:   map[string]string{"X-Ratelimit-Remaining": "0"},
			wantErr:   true,
			wantRetry: true,
		},
		{
			name:     "malformed response",
			status:   http.StatusOK,
			response: `not json`,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var gotPath, gotQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotQuery = r.URL.Path, r.URL.Query().Get("q")
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer srv.Close()

			got, err := New(srv.URL, "test-token").FindOpenIssue(t.Context(), "myorg/myrepo", "dtgn-0123")

			if (err != nil) != tc.wantErr {
				t.Fatalf("FindOpenIssue() error = %v, wantErr %v", err, tc.wantErr)
			}
			if _, retry := retryable.As(err); retry != tc.wantRetry {
				t.Errorf("FindOpenIssue() retryable = %v, want %v", retry, tc.wantRetry)
			}
			if got != tc.want {
				t.Errorf("FindOpenIssue() = %q, want %q", got, tc.want)
			}
			if wantQuery := `repo:myorg/myrepo is:issue is:open in:body "dtgn-0123"`; gotPath != "/search/issues" || gotQuery != wantQuery {
				t.Errorf("request path = %q, q = %q, want /search/issues, %q", gotPath, gotQuery, wantQuery)
			}
		})
	}
}
