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

type fakeIssueCreator struct {
	err error

	called bool
	repo   string
	issue  issue.Issue
}

func (f *fakeIssueCreator) CreateIssue(_ context.Context, repo string, i issue.Issue) error {
	f.called, f.repo, f.issue = true, repo, i
	return f.err
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
			issues := &fakeIssueCreator{}
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
			issues := &fakeIssueCreator{err: tc.createErr}
			repos := &fakeResolver{repo: "myorg/my-service", err: tc.resolveErr}

			rec := serve(t, New(issues, repos, tc.secret), tc.method, tc.body, tc.signature)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}
			if issues.called != tc.wantCreate {
				t.Errorf("issue creation attempted = %v, want %v", issues.called, tc.wantCreate)
			}
		})
	}
}
