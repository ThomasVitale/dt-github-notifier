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
	public    bool // returned by IsPublic
	publicErr error
	existing  issue.Ref // returned by FindOpenIssue
	findErr   error
	createErr error
	closeErr  error

	finds   int
	creates int
	closes  int
	repo    string
	issue   issue.Issue
	closed  int // number of the last closed issue
	closure issue.Closure
}

func (f *fakeIssueTracker) IsPublic(context.Context, string) (bool, error) {
	return f.public, f.publicErr
}

func (f *fakeIssueTracker) FindOpenIssue(_ context.Context, repo, key string) (issue.Ref, error) {
	f.finds++
	f.repo = repo
	f.issue.Key = key
	return f.existing, f.findErr
}

func (f *fakeIssueTracker) CreateIssue(_ context.Context, repo string, i issue.Issue) (issue.Ref, error) {
	f.creates++
	f.repo, f.issue = repo, i
	if f.createErr != nil {
		return issue.Ref{}, f.createErr
	}
	return issue.Ref{Number: 100 + f.creates, URL: "https://github.com/" + repo + "/issues/new"}, nil
}

func (f *fakeIssueTracker) CloseIssue(_ context.Context, repo string, number int, c issue.Closure) error {
	f.closes++
	f.repo, f.closed, f.closure = repo, number, c
	return f.closeErr
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
		{notificationtest.PolicyViolation, "policy-violation"},
	}

	for _, tc := range tests {
		t.Run(tc.payload, func(t *testing.T) {
			t.Parallel()
			repos := &fakeResolver{repo: "myorg/my-service"}
			issues := &fakeIssueTracker{}
			rec := serve(t, New(issues, repos, Options{}), http.MethodPost, notificationtest.Payload(t, tc.payload), "")

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
		public         bool
		allowPublic    bool
		publicErr      error
		findErr        error
		existing       issue.Ref
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
			name:       "ignores new vulnerable dependency",
			body:       notificationtest.Payload(t, notificationtest.NewVulnerableDependency),
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
			name:       "public repo is refused",
			body:       vuln,
			public:     true,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:        "public repo is allowed when configured",
			body:        vuln,
			public:      true,
			allowPublic: true,
			wantStatus:  http.StatusNoContent,
			wantCreate:  true,
		},
		{
			name:       "transient visibility check failure asks DT to retry",
			body:       vuln,
			publicErr:  retryable.Wrap(errors.New("unavailable"), 0),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "existing open issue is not duplicated",
			body:       vuln,
			existing:   issue.Ref{Number: 7, URL: "https://github.com/myorg/my-service/issues/7"},
			wantStatus: http.StatusNoContent,
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
			issues := &fakeIssueTracker{
				public: tc.public, publicErr: tc.publicErr,
				existing: tc.existing, findErr: tc.findErr, createErr: tc.createErr,
			}
			repos := &fakeResolver{repo: "myorg/my-service", err: tc.resolveErr}

			h := New(issues, repos, Options{Secret: tc.secret, AllowPublicRepos: tc.allowPublic})
			rec := serve(t, h, tc.method, tc.body, tc.signature)

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
	h := New(issues, &fakeResolver{repo: "myorg/my-service"}, Options{})
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

	a := issue.Ref{Number: 1, URL: "url-a"}
	r.add("a", a)
	if ref, ok := r.get("a"); !ok || ref != a {
		t.Errorf("get(a) = %+v, %v, want %+v, true", ref, ok, a)
	}
	if _, ok := r.get("b"); ok {
		t.Error("get(b) found an entry never added")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := r.get("a"); ok {
		t.Error("get(a) found an expired entry")
	}

	r.add("b", issue.Ref{Number: 2})
	r.add("c", issue.Ref{Number: 3}) // evicts expired "a"
	r.add("d", issue.Ref{Number: 4}) // full: evicts one of "b" and "c"
	if len(r.entries) != 2 {
		t.Errorf("%d entries, want at most 2", len(r.entries))
	}
	if _, ok := r.get("d"); !ok {
		t.Error("get(d) did not find the latest entry")
	}

	r.remove("d")
	if _, ok := r.get("d"); ok {
		t.Error("get(d) found a removed entry")
	}
}

// ── closing issues ────────────────────────────────────────────────────────────

func TestClosesIssues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		payload    string
		openedBy   string // payload creating the issue to close
		wantReason string
		wantText   string
	}{
		{
			payload:    notificationtest.ProjectAuditChangeVulnerability,
			openedBy:   notificationtest.NewVulnerability,
			wantReason: issue.ReasonNotPlanned,
			wantText:   "is `FALSE_POSITIVE` and the vulnerability is suppressed",
		},
		{
			payload:    notificationtest.ProjectAuditChangePolicyViolation,
			openedBy:   notificationtest.PolicyViolation,
			wantReason: issue.ReasonNotPlanned,
			wantText:   "policy violation is `REJECTED` and the policy violation is suppressed",
		},
		{
			payload:    notificationtest.VulnerabilityRetracted,
			openedBy:   notificationtest.NewVulnerability,
			wantReason: issue.ReasonNotPlanned,
			wantText:   "retracted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.payload, func(t *testing.T) {
			t.Parallel()
			repos := &fakeResolver{repo: "myorg/my-service"}

			// The key of the issue the creating notification would open.
			creator := &fakeIssueTracker{}
			serve(t, New(creator, repos, Options{}), http.MethodPost, notificationtest.Payload(t, tc.openedBy), "")
			wantKey := creator.issue.Key

			issues := &fakeIssueTracker{existing: issue.Ref{Number: 7, URL: "https://github.com/myorg/my-service/issues/7"}}
			rec := serve(t, New(issues, repos, Options{}), http.MethodPost, notificationtest.Payload(t, tc.payload), "")

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body)
			}
			if issues.issue.Key != wantKey {
				t.Errorf("searched for key %q, want %q, the key of the issue to close", issues.issue.Key, wantKey)
			}
			if issues.closes != 1 || issues.closed != 7 || issues.repo != "myorg/my-service" {
				t.Fatalf("closed %d issues (last #%d in %q), want #7 in myorg/my-service", issues.closes, issues.closed, issues.repo)
			}
			if issues.closure.Reason != tc.wantReason || !strings.Contains(issues.closure.Comment, tc.wantText) {
				t.Errorf("closure = %+v, want reason %q and comment containing %q", issues.closure, tc.wantReason, tc.wantText)
			}
		})
	}
}

func TestCloseWithoutOpenIssue(t *testing.T) {
	t.Parallel()
	issues := &fakeIssueTracker{}
	rec := serve(t, New(issues, &fakeResolver{repo: "myorg/my-service"}, Options{}), http.MethodPost,
		notificationtest.Payload(t, notificationtest.VulnerabilityRetracted), "")
	if rec.Code != http.StatusNoContent || issues.finds != 1 || issues.closes != 0 {
		t.Errorf("status %d, %d searches, %d closes; want 204, 1, 0", rec.Code, issues.finds, issues.closes)
	}
}

func TestAuditDecisionLeavingFindingOpen(t *testing.T) {
	t.Parallel()
	body := notificationtest.Payload(t, notificationtest.ProjectAuditChangeVulnerability)
	body = bytes.ReplaceAll(body, []byte(`"FALSE_POSITIVE"`), []byte(`"EXPLOITABLE"`))
	body = bytes.ReplaceAll(body, []byte(`"suppressed": true`), []byte(`"suppressed": false`))
	if bytes.Contains(body, []byte("FALSE_POSITIVE")) || bytes.Contains(body, []byte(`"suppressed": true`)) {
		t.Fatal("fixture not modified")
	}
	issues := &fakeIssueTracker{}
	repos := &fakeResolver{}
	rec := serve(t, New(issues, repos, Options{}), http.MethodPost, body, "")
	if rec.Code != http.StatusNoContent || repos.called || issues.finds != 0 || issues.closes != 0 {
		t.Errorf("status %d, resolved %v, %d searches, %d closes; want 204 and no other calls",
			rec.Code, repos.called, issues.finds, issues.closes)
	}
}

func TestCloseRecentIssueAndReopen(t *testing.T) {
	t.Parallel()
	issues := &fakeIssueTracker{}
	h := New(issues, &fakeResolver{repo: "myorg/my-service"}, Options{})

	serve(t, h, http.MethodPost, notificationtest.Payload(t, notificationtest.NewVulnerability), "")
	created := issues.creates

	// Search would not return the new issue yet; the handler remembers it.
	rec := serve(t, h, http.MethodPost, notificationtest.Payload(t, notificationtest.VulnerabilityRetracted), "")
	if rec.Code != http.StatusNoContent || issues.closes != 1 || issues.closed != 100+created {
		t.Fatalf("status %d, closed %d issues (last #%d), want the issue just created, #%d",
			rec.Code, issues.closes, issues.closed, 100+created)
	}

	// Once closed, a new notification for the finding opens a new issue.
	serve(t, h, http.MethodPost, notificationtest.Payload(t, notificationtest.NewVulnerability), "")
	if issues.creates != created+1 {
		t.Errorf("created %d issues, want %d after the first was closed", issues.creates, created+1)
	}
}

func TestCloseFailures(t *testing.T) {
	t.Parallel()
	body := notificationtest.Payload(t, notificationtest.VulnerabilityRetracted)
	tests := []struct {
		name       string
		issues     *fakeIssueTracker
		wantStatus int
	}{
		{"transient search failure", &fakeIssueTracker{findErr: retryable.Wrap(errors.New("down"), 0)}, http.StatusServiceUnavailable},
		{"transient close failure", &fakeIssueTracker{existing: issue.Ref{Number: 7}, closeErr: retryable.Wrap(errors.New("down"), 0)}, http.StatusServiceUnavailable},
		{"permanent close failure", &fakeIssueTracker{existing: issue.Ref{Number: 7}, closeErr: errors.New("forbidden")}, http.StatusInternalServerError},
	}
	for _, tc := range tests {
		rec := serve(t, New(tc.issues, &fakeResolver{repo: "myorg/my-service"}, Options{}), http.MethodPost, body, "")
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.wantStatus)
		}
	}
}

// ── notification age ──────────────────────────────────────────────────────────

func TestNotificationAge(t *testing.T) {
	t.Parallel()
	// The fixtures' ID is a UUIDv7, which embeds its creation time.
	const id = "010ba7f2-ab4a-73b6-a87d-7b9041d17016"
	created := time.Unix(uuid.MustParse(id).Time().UnixTime())
	vuln := notificationtest.Payload(t, notificationtest.NewVulnerability)

	tests := []struct {
		name       string
		now        time.Time
		body       []byte
		wantStatus int
	}{
		{"recent", created.Add(time.Hour), vuln, http.StatusNoContent},
		{"slightly in the future", created.Add(-time.Minute), vuln, http.StatusNoContent},
		{"too old", created.Add(25 * time.Hour), vuln, http.StatusBadRequest},
		{"far in the future", created.Add(-time.Hour), vuln, http.StatusBadRequest},
		{"not a UUIDv7", created, bytes.Replace(vuln, []byte(id), []byte(uuid.NewString()), 1), http.StatusBadRequest},
	}
	for _, tc := range tests {
		issues := &fakeIssueTracker{}
		h := New(issues, &fakeResolver{repo: "myorg/my-service"}, Options{MaxNotificationAge: 24 * time.Hour})
		h.now = func() time.Time { return tc.now }
		if rec := serve(t, h, http.MethodPost, tc.body, ""); rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.wantStatus)
		}
	}
}
