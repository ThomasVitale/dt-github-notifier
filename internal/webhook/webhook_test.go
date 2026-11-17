package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/thomasvitale/dt-github-notifier/internal/issue"
	"github.com/thomasvitale/dt-github-notifier/internal/notification/notificationtest"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeResolver struct {
	repo string
	err  error

	called      bool
	projectUUID uuid.UUID
	hasDeadline bool
}

func (f *fakeResolver) Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error) {
	f.called, f.projectUUID = true, projectUUID
	_, f.hasDeadline = ctx.Deadline()
	return f.repo, f.err
}

type fakeIssueTracker struct {
	existingURL string // returned by FindOpenIssue
	findErr     error
	createErr   error

	finds   int
	creates int
	repo    string
	issue   issue.Issue
}

func (f *fakeIssueTracker) FindOpenIssue(_ context.Context, repo, key string) (string, error) {
	f.finds++
	f.repo = repo
	f.issue.Key = key
	return f.existingURL, f.findErr
}

func (f *fakeIssueTracker) CreateIssue(_ context.Context, repo string, i issue.Issue) (string, error) {
	f.creates++
	f.repo, f.issue = repo, i
	if f.createErr != nil {
		return "", f.createErr
	}
	return "https://github.com/" + repo + "/issues/1", nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func serve(t *testing.T, h http.Handler, method string, body []byte, signature string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/webhook", bytes.NewReader(body))
	if signature != "" {
		req.Header.Set(signatureHeader, signature)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestCreatesIssueInResolvedRepo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		payload   string
		wantLabel string
	}{
		{notificationtest.NewVulnerability, "vulnerability"},
		{notificationtest.NewVulnerableDependency, "vulnerable-dependency"},
		{notificationtest.PolicyViolation, "policy-violation"},
	}

	for _, tc := range tests {
		t.Run(tc.payload, func(t *testing.T) {
			t.Parallel()
			repos := &fakeResolver{repo: "myorg/my-service"}
			issues := &fakeIssueTracker{}
			rec := serve(t, New(issues, repos, ""), http.MethodPost, notificationtest.Payload(t, tc.payload), "")

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body)
			}
			if want := uuid.MustParse("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"); repos.projectUUID != want {
				t.Errorf("resolved project %s, want %s", repos.projectUUID, want)
			}
			if !repos.hasDeadline {
				t.Error("resolver context has no deadline")
			}
			if issues.finds != 1 || issues.creates != 1 {
				t.Errorf("searched %d and created %d issues, want 1 and 1", issues.finds, issues.creates)
			}
			if issues.repo != "myorg/my-service" {
				t.Errorf("issue created in %q, want myorg/my-service", issues.repo)
			}
			if !strings.HasPrefix(issues.issue.Title, "[DT] ") || !slices.Contains(issues.issue.Labels, tc.wantLabel) {
				t.Errorf("issue = %q %v, want [DT] title and label %q", issues.issue.Title, issues.issue.Labels, tc.wantLabel)
			}
		})
	}
}

func TestResponses(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t"
	vuln := notificationtest.Payload(t, notificationtest.NewVulnerability)

	tests := []struct {
		name           string
		method         string
		body           []byte
		signature      string // X-Webhook-Signature header, if any
		secret         string
		resolveErr     error
		findErr        error
		existingURL    string
		createErr      error
		wantStatus     int
		wantRetryAfter string
		wantCreate     bool // whether an issue creation is attempted
	}{
		{
			name:       "rejects non-POST",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "rejects malformed JSON",
			body:       []byte(`{"notification":`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects payload without group",
			body:       []byte(`{"notification":{"id":"x"}}`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects subject without valid project UUID",
			body:       []byte(`{"notification":{"group":"GROUP_NEW_VULNERABILITY","subject":{"project":{"uuid":"nope"}}}}`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects handled group without subject",
			body:       []byte(`{"notification":{"group":"GROUP_POLICY_VIOLATION"}}`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejects oversized body",
			body:       bytes.Repeat([]byte(" "), maxRequestBodyBytes+1),
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "ignores unhandled group",
			body:       notificationtest.Payload(t, notificationtest.BOMConsumed),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "ignores v4 group names",
			body:       []byte(`{"notification":{"group":"NEW_VULNERABILITY","subject":{}}}`),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "accepts valid signature",
			body:       vuln,
			secret:     secret,
			signature:  sign(secret, vuln),
			wantStatus: http.StatusNoContent,
			wantCreate: true,
		},
		{
			name:       "rejects missing signature",
			body:       vuln,
			secret:     secret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "rejects signature made with another secret",
			body:       vuln,
			secret:     secret,
			signature:  sign("other", vuln),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "rejects malformed signature",
			body:       vuln,
			secret:     secret,
			signature:  "sha256=zz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "no resolvable repo is unprocessable",
			body:       vuln,
			resolveErr: fmt.Errorf("%w for project x", resolver.ErrNoRepo),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "transient resolution failure asks DT to retry",
			body:       vuln,
			resolveErr: retryable.Wrap(errors.New("connection refused"), 0),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "permanent resolution failure",
			body:       vuln,
			resolveErr: errors.New("forbidden"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:           "transient GitHub failure asks DT to retry after the given delay",
			body:           vuln,
			createErr:      retryable.Wrap(errors.New("rate limited"), 1500*time.Millisecond),
			wantStatus:     http.StatusServiceUnavailable,
			wantRetryAfter: "2",
			wantCreate:     true,
		},
		{
			name:        "existing open issue is not duplicated",
			body:        vuln,
			existingURL: "https://github.com/myorg/my-service/issues/7",
			wantStatus:  http.StatusNoContent,
		},
		{
			name:       "transient search failure asks DT to retry",
			body:       vuln,
			findErr:    retryable.Wrap(errors.New("search rate limited"), 30*time.Second),
			wantStatus: http.StatusServiceUnavailable,

			wantRetryAfter: "30",
		},
		{
			name:       "permanent GitHub failure",
			body:       vuln,
			createErr:  errors.New("not found"),
			wantStatus: http.StatusInternalServerError,
			wantCreate: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.method == "" {
				tc.method = http.MethodPost
			}
			issues := &fakeIssueTracker{existingURL: tc.existingURL, findErr: tc.findErr, createErr: tc.createErr}
			repos := &fakeResolver{repo: "myorg/my-service", err: tc.resolveErr}

			rec := serve(t, New(issues, repos, tc.secret), tc.method, tc.body, tc.signature)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}
			if created := issues.creates > 0; created != tc.wantCreate {
				t.Errorf("issue creation attempted = %v, want %v", created, tc.wantCreate)
			}
		})
	}
}

func TestRepeatedNotificationUsesRecentIssue(t *testing.T) {
	t.Parallel()
	issues := &fakeIssueTracker{}
	h := New(issues, &fakeResolver{repo: "myorg/my-service"}, "")
	body := notificationtest.Payload(t, notificationtest.NewVulnerability)

	for range 3 {
		if rec := serve(t, h, http.MethodPost, body, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	}
	// The search index may not contain the new issue yet: retries must not
	// depend on it.
	if issues.finds != 1 || issues.creates != 1 {
		t.Errorf("searched %d and created %d issues, want 1 and 1", issues.finds, issues.creates)
	}

	// Another repo is a different issue.
	h.repos = &fakeResolver{repo: "myorg/other"}
	serve(t, h, http.MethodPost, body, "")
	if issues.creates != 2 {
		t.Errorf("created %d issues, want 2 after a notification for another repo", issues.creates)
	}
}

func TestRecentIssues(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	r := newRecentIssues(time.Minute, 2)
	r.now = func() time.Time { return now }

	r.add("a", "url-a")
	if url, ok := r.get("a"); !ok || url != "url-a" {
		t.Errorf("get(a) = %q, %v, want url-a, true", url, ok)
	}
	if _, ok := r.get("b"); ok {
		t.Error("get(b) found an entry never added")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := r.get("a"); ok {
		t.Error("get(a) found an expired entry")
	}

	r.add("b", "url-b")
	r.add("c", "url-c") // evicts expired "a"
	r.add("d", "url-d") // full: evicts one of "b" and "c"
	if len(r.entries) != 2 {
		t.Errorf("%d entries, want at most 2", len(r.entries))
	}
	if _, ok := r.get("d"); !ok {
		t.Error("get(d) did not find the latest entry")
	}
}
