package config

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
)

var envVars = []string{
	"GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_API_URL", "GITHUB_ALLOWED_REPOS", "ALLOW_PUBLIC_REPOS",
	"REPO_SOURCES", "DT_BASE_URL", "DT_API_KEY", "DT_WEBHOOK_SECRET", "ALLOW_UNSIGNED_WEBHOOKS",
	"PORT", "LOG_LEVEL",
}

func TestFromEnv(t *testing.T) {
	valid := map[string]string{
		"GITHUB_TOKEN":         "ghp_x",
		"GITHUB_ALLOWED_REPOS": "myorg/*",
		"DT_BASE_URL":          "http://dt.example:8080",
		"DT_API_KEY":           "key",
		"DT_WEBHOOK_SECRET":    "s3cr3t",
	}
	mustAllowlist := func(patterns ...string) *github.Allowlist {
		a, err := github.NewAllowlist(patterns)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	tests := []struct {
		name    string
		env     map[string]string // overrides on top of valid; "" unsets
		want    Config
		wantErr string
	}{
		{
			name: "defaults",
			want: Config{
				GitHubToken:   "ghp_x",
				GitHubAPIURL:  "https://api.github.com",
				AllowedRepos:  mustAllowlist("myorg/*"),
				RepoSources:   resolver.AllSources,
				DTBaseURL:     "http://dt.example:8080",
				DTAPIKey:      "key",
				WebhookSecret: "s3cr3t",
				Port:          "8080",
			},
		},
		{
			name: "all set",
			env: map[string]string{
				"GITHUB_REPO":             "myorg/myrepo",
				"GITHUB_API_URL":          "https://ghe.example/api/v3",
				"GITHUB_ALLOWED_REPOS":    "myorg/myrepo, otherorg/*",
				"ALLOW_PUBLIC_REPOS":      "true",
				"REPO_SOURCES":            "property",
				"DT_WEBHOOK_SECRET":       "",
				"ALLOW_UNSIGNED_WEBHOOKS": "true",
				"PORT":                    "9090",
				"LOG_LEVEL":               "DEBUG",
			},
			want: Config{
				GitHubToken:           "ghp_x",
				GitHubRepo:            "myorg/myrepo",
				GitHubAPIURL:          "https://ghe.example/api/v3",
				AllowedRepos:          mustAllowlist("myorg/myrepo", "otherorg/*"),
				AllowPublicRepos:      true,
				RepoSources:           []resolver.Source{resolver.SourceProperty},
				DTBaseURL:             "http://dt.example:8080",
				DTAPIKey:              "key",
				AllowUnsignedWebhooks: true,
				Port:                  "9090",
				LogLevel:              slog.LevelDebug,
			},
		},
		{name: "missing GitHub token", env: map[string]string{"GITHUB_TOKEN": ""}, wantErr: "GITHUB_TOKEN"},
		{name: "missing allowed repos", env: map[string]string{"GITHUB_ALLOWED_REPOS": ""}, wantErr: "GITHUB_ALLOWED_REPOS"},
		{name: "invalid allowed repos", env: map[string]string{"GITHUB_ALLOWED_REPOS": "myorg"}, wantErr: "GITHUB_ALLOWED_REPOS"},
		{name: "fallback repo not allowed", env: map[string]string{"GITHUB_REPO": "otherorg/repo"}, wantErr: "GITHUB_ALLOWED_REPOS"},
		{name: "invalid fallback repo", env: map[string]string{"GITHUB_REPO": "not a repo"}, wantErr: "GITHUB_REPO"},
		{name: "invalid repo sources", env: map[string]string{"REPO_SOURCES": "vcs,git"}, wantErr: "REPO_SOURCES"},
		{name: "invalid GitHub API URL", env: map[string]string{"GITHUB_API_URL": "api.github.com"}, wantErr: "GITHUB_API_URL"},
		{name: "plain HTTP GitHub API URL", env: map[string]string{"GITHUB_API_URL": "http://ghe.example/api/v3"}, wantErr: "https"},
		{name: "missing DT base URL", env: map[string]string{"DT_BASE_URL": ""}, wantErr: "DT_BASE_URL"},
		{name: "invalid DT base URL", env: map[string]string{"DT_BASE_URL": "dt.example"}, wantErr: "DT_BASE_URL"},
		{
			name:    "DT base URL password is not echoed",
			env:     map[string]string{"DT_BASE_URL": "ftp://user:hunter2@dt.example"},
			wantErr: "user:xxxxx@dt.example",
		},
		{name: "missing DT API key", env: map[string]string{"DT_API_KEY": ""}, wantErr: "DT_API_KEY"},
		{name: "missing webhook secret", env: map[string]string{"DT_WEBHOOK_SECRET": ""}, wantErr: "DT_WEBHOOK_SECRET"},
		{name: "invalid boolean", env: map[string]string{"ALLOW_PUBLIC_REPOS": "yes please"}, wantErr: "ALLOW_PUBLIC_REPOS"},
		{name: "invalid log level", env: map[string]string{"LOG_LEVEL": "verbose"}, wantErr: "LOG_LEVEL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel
			for _, k := range envVars {
				t.Setenv(k, valid[k])
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			got, err := FromEnv()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("FromEnv() error = %v, want error containing %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "hunter2") {
					t.Errorf("FromEnv() error %q leaks a password", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromEnv() unexpected error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FromEnv() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRedactedDTBaseURL(t *testing.T) {
	t.Parallel()
	cfg := Config{DTBaseURL: "https://user:hunter2@dt.example/api"}
	if got := cfg.RedactedDTBaseURL(); got != "https://user:xxxxx@dt.example/api" {
		t.Errorf("RedactedDTBaseURL() = %q", got)
	}
}
