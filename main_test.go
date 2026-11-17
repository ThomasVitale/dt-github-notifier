package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/thomasvitale/dt-github-notifier/internal/config"
	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/notification/notificationtest"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
)

const (
	projectUUID   = "c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
	webhookSecret = "s3cr3t"
)

type gitHubRequest struct {
	path, auth string
	body       map[string]any
}

type testService struct {
	url string
	// created receives the issue creation requests.
	created chan gitHubRequest
	// gitHubCalls counts all GitHub API requests.
	gitHubCalls atomic.Int32
}

// newTestService starts the fully wired service, backed by fake
// Dependency-Track and GitHub APIs. The project's vcs external reference
// points to vcsURL, and only myorg/* repositories are allowed.
func newTestService(t *testing.T, vcsURL string) *testService {
	t.Helper()
	s := &testService{created: make(chan gitHubRequest, 2)}

	dt := http.NewServeMux()
	dt.HandleFunc("GET /api/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"5.2.0"}`))
	})
	dt.HandleFunc("GET /api/v1/project/"+projectUUID, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "dt-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":               "projectName",
			"externalReferences": []map[string]string{{"type": "vcs", "url": vcsURL}},
		})
	})
	dtServer := httptest.NewServer(dt)
	t.Cleanup(dtServer.Close)

	gitHub := http.NewServeMux()
	gitHub.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"private":true,"visibility":"private"}`))
	})
	gitHub.HandleFunc("GET /search/issues", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	})
	gitHub.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		req := gitHubRequest{path: r.URL.Path, auth: r.Header.Get("Authorization")}
		_ = json.NewDecoder(r.Body).Decode(&req.body)
		s.created <- req
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"html_url":"https://github.com/myorg/my-service/issues/1"}`))
	})
	gitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.gitHubCalls.Add(1)
		gitHub.ServeHTTP(w, r)
	}))
	t.Cleanup(gitHubServer.Close)

	allowed, err := github.NewAllowlist([]string{"myorg/*"})
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(newHandler(config.Config{
		GitHubToken:   "gh-token",
		GitHubAPIURL:  gitHubServer.URL,
		AllowedRepos:  allowed,
		RepoSources:   resolver.AllSources,
		DTBaseURL:     dtServer.URL,
		DTAPIKey:      "dt-key",
		WebhookSecret: webhookSecret,
	}))
	t.Cleanup(service.Close)
	s.url = service.URL
	return s
}

// send posts a signed notification and returns the response status.
func (s *testService) send(t *testing.T, body []byte) int {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.url+"/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestEndToEnd(t *testing.T) {
	t.Parallel()
	s := newTestService(t, "https://github.com/myorg/my-service.git")
	body := notificationtest.Payload(t, notificationtest.NewVulnerability)

	// The second, identical notification (e.g. a DT retry) must not create
	// another issue.
	for range 2 {
		if status := s.send(t, body); status != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", status, http.StatusNoContent)
		}
	}
	if n := len(s.created); n != 1 {
		t.Fatalf("created %d issues, want 1", n)
	}

	got := <-s.created
	if got.path != "/repos/myorg/my-service/issues" || got.auth != "Bearer gh-token" {
		t.Errorf("GitHub request path = %q, Authorization = %q", got.path, got.auth)
	}
	if got.body["title"] != "[DT] INT-001 (MEDIUM) in componentName componentVersion" {
		t.Errorf("issue title = %v", got.body["title"])
	}
}

// TestEndToEndDisallowedRepo checks that a repo outside GITHUB_ALLOWED_REPOS,
// which anyone able to upload a BOM can set as the project's vcs reference,
// is never contacted.
func TestEndToEndDisallowedRepo(t *testing.T) {
	t.Parallel()
	s := newTestService(t, "https://github.com/attacker/repo")

	if status := s.send(t, notificationtest.Payload(t, notificationtest.NewVulnerability)); status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	if n := s.gitHubCalls.Load(); n != 0 {
		t.Errorf("made %d GitHub requests, want 0", n)
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	allowed, err := github.NewAllowlist([]string{"myorg/*"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	newHandler(config.Config{DTBaseURL: "http://127.0.0.1:1", AllowedRepos: allowed}).ServeHTTP(rec,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("GET /healthz = %d %q, want 200 ok", rec.Code, rec.Body)
	}
}
