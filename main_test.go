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
	"testing"

	"github.com/thomasvitale/dt-github-notifier/internal/config"
	"github.com/thomasvitale/dt-github-notifier/internal/notification/notificationtest"
)

// TestEndToEnd sends a signed notification through the fully wired service,
// backed by fake Dependency-Track and GitHub APIs.
func TestEndToEnd(t *testing.T) {
	t.Parallel()
	const projectUUID = "c9c9539a-e381-4b36-ac52-6a7ab83b2c95"

	dt := http.NewServeMux()
	dt.HandleFunc("GET /api/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"5.2.0"}`))
	})
	dt.HandleFunc("GET /api/v1/project/"+projectUUID, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "dt-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"projectName","externalReferences":[{"type":"vcs","url":"https://github.com/myorg/my-service.git"}]}`))
	})
	dtServer := httptest.NewServer(dt)
	defer dtServer.Close()

	type gitHubRequest struct {
		path, auth string
		body       map[string]any
	}
	gitHubRequests := make(chan gitHubRequest, 1)
	gitHubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := gitHubRequest{path: r.URL.Path, auth: r.Header.Get("Authorization")}
		_ = json.NewDecoder(r.Body).Decode(&req.body)
		gitHubRequests <- req
		w.WriteHeader(http.StatusCreated)
	}))
	defer gitHubServer.Close()

	service := httptest.NewServer(newHandler(config.Config{
		GitHubToken:   "gh-token",
		GitHubAPIURL:  gitHubServer.URL,
		DTBaseURL:     dtServer.URL,
		DTAPIKey:      "dt-key",
		WebhookSecret: "s3cr3t",
	}))
	defer service.Close()

	body := notificationtest.Payload(t, notificationtest.NewVulnerability)
	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write(body)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, service.URL+"/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusNoContent, msg)
	}

	got := <-gitHubRequests
	if got.path != "/repos/myorg/my-service/issues" || got.auth != "Bearer gh-token" {
		t.Errorf("GitHub request path = %q, Authorization = %q", got.path, got.auth)
	}
	if got.body["title"] != "[DT] INT-001 (MEDIUM) in componentName componentVersion" {
		t.Errorf("issue title = %v", got.body["title"])
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	newHandler(config.Config{DTBaseURL: "http://127.0.0.1:1"}).ServeHTTP(rec,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("GET /healthz = %d %q, want 200 ok", rec.Code, rec.Body)
	}
}
