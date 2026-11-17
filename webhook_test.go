package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
)

// ── fake GitHub API ───────────────────────────────────────────────────────────

type gitHubRequest struct {
	path  string
	auth  string
	issue gitHubIssueRequest
}

// newFakeGitHub starts a GitHub API stub that records every request and
// answers with the given status and headers.
func newFakeGitHub(t *testing.T, status int, headers map[string]string) (*gitHubClient, chan gitHubRequest) {
	t.Helper()
	requests := make(chan gitHubRequest, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var issue gitHubIssueRequest
		_ = json.NewDecoder(r.Body).Decode(&issue)
		requests <- gitHubRequest{path: r.URL.Path, auth: r.Header.Get("Authorization"), issue: issue}
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"stub"}`))
	}))
	t.Cleanup(srv.Close)
	return newGitHubClient(srv.URL, "test-token"), requests
}

// ── helpers ───────────────────────────────────────────────────────────────────

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func gitHubProject() *fakeProjectFetcher {
	return &fakeProjectFetcher{
		project: dtrack.Project{
			Name: "projectName",
			ExternalReferences: []dtrack.ExternalReference{
				{Type: "vcs", URL: "https://github.com/myorg/my-service"},
			},
		},
	}
}

// ── handleWebhook ─────────────────────────────────────────────────────────────

func TestHandleWebhookCreatesIssue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture    string
		wantTitle  string
		wantLabels []string
		wantInBody []string
	}{
		{
			fixture:    "new_vulnerability.json",
			wantTitle:  "[DT] INT-001 (MEDIUM) in componentName componentVersion",
			wantLabels: []string{"security", "vulnerability", "dependency-track", "severity:medium"},
			wantInBody: []string{"| **Aliases** | OSV-001 |", "| **CVSS Score** | 7.7 (v4) |", "vulnerabilityRecommendation"},
		},
		{
			fixture:    "new_vulnerable_dependency.json",
			wantTitle:  "[DT] Vulnerable Dependency: componentName componentVersion introduced in projectName projectVersion",
			wantLabels: []string{"security", "vulnerable-dependency", "dependency-track"},
			wantInBody: []string{"- **INT-001** (MEDIUM) — INTERNAL"},
		},
		{
			fixture:    "policy_violation.json",
			wantTitle:  "[DT] Policy Violation: policyName in projectName projectVersion",
			wantLabels: []string{"security", "policy-violation", "dependency-track", "violation-state:fail"},
			wantInBody: []string{"| **Condition** | PACKAGE_URL IS pkg:maven/foo/bar@1.2.3 |", "is not allowed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			gh, requests := newFakeGitHub(t, http.StatusCreated, nil)
			h := newWebhookHandler(gh, newTestResolver(gitHubProject(), ""), "")

			rec := httptest.NewRecorder()
			h.handleWebhook(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/webhook", bytes.NewReader(readFixture(t, tc.fixture))))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body)
			}
			req := <-requests
			if req.path != "/repos/myorg/my-service/issues" {
				t.Errorf("path = %q, want /repos/myorg/my-service/issues", req.path)
			}
			if req.auth != "Bearer test-token" {
				t.Errorf("Authorization = %q", req.auth)
			}
			if req.issue.Title != tc.wantTitle {
				t.Errorf("title = %q, want %q", req.issue.Title, tc.wantTitle)
			}
			if !slices.Equal(req.issue.Labels, tc.wantLabels) {
				t.Errorf("labels = %v, want %v", req.issue.Labels, tc.wantLabels)
			}
			for _, want := range tc.wantInBody {
				if !strings.Contains(req.issue.Body, want) {
					t.Errorf("body does not contain %q:\n%s", want, req.issue.Body)
				}
			}
		})
	}
}

func TestHandleWebhookResponses(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t"
	vuln := readFixture(t, "new_vulnerability.json")

	tests := []struct {
		name           string
		method         string
		body           []byte
		signature      string // X-Webhook-Signature header, if any
		secret         string
		fetcher        *fakeProjectFetcher
		defaultRepo    string
		ghStatus       int
		ghHeaders      map[string]string
		wantStatus     int
		wantRetryAfter string
		wantGitHub     bool // whether an issue creation is attempted
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
			body:       readFixture(t, "bom_consumed.json"),
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
			wantGitHub: true,
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
			fetcher:    &fakeProjectFetcher{project: dtrack.Project{Name: "projectName"}},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "transient DT failure asks DT to retry",
			body:       vuln,
			fetcher:    &fakeProjectFetcher{projectErr: errors.New("connection refused")},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "falls back to default repo",
			body:       vuln,
			fetcher:    &fakeProjectFetcher{project: dtrack.Project{Name: "projectName"}},
			wantStatus: http.StatusNoContent,
			wantGitHub: true,

			defaultRepo: "myorg/fallback",
		},
		{
			name:           "GitHub rate limit asks DT to retry after the given delay",
			body:           vuln,
			ghStatus:       http.StatusForbidden,
			ghHeaders:      map[string]string{"Retry-After": "60"},
			wantStatus:     http.StatusServiceUnavailable,
			wantRetryAfter: "60",
			wantGitHub:     true,
		},
		{
			name:       "GitHub server error asks DT to retry",
			body:       vuln,
			ghStatus:   http.StatusBadGateway,
			wantStatus: http.StatusServiceUnavailable,
			wantGitHub: true,
		},
		{
			name:       "GitHub client error is permanent",
			body:       vuln,
			ghStatus:   http.StatusNotFound,
			wantStatus: http.StatusInternalServerError,
			wantGitHub: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.method == "" {
				tc.method = http.MethodPost
			}
			if tc.fetcher == nil {
				tc.fetcher = gitHubProject()
			}
			if tc.ghStatus == 0 {
				tc.ghStatus = http.StatusCreated
			}
			gh, requests := newFakeGitHub(t, tc.ghStatus, tc.ghHeaders)
			h := newWebhookHandler(gh, newTestResolver(tc.fetcher, tc.defaultRepo), tc.secret)

			req := httptest.NewRequestWithContext(t.Context(), tc.method, "/webhook", bytes.NewReader(tc.body))
			if tc.signature != "" {
				req.Header.Set(signatureHeader, tc.signature)
			}
			rec := httptest.NewRecorder()
			h.handleWebhook(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}
			if gotGitHub := len(requests) > 0; gotGitHub != tc.wantGitHub {
				t.Errorf("GitHub called = %v, want %v", gotGitHub, tc.wantGitHub)
			}
		})
	}
}
