package config

import (
	"log/slog"
	"strings"
	"testing"
)

func TestFromEnv(t *testing.T) {
	valid := map[string]string{
		"GITHUB_TOKEN": "ghp_x",
		"DT_BASE_URL":  "http://dt.example:8080",
		"DT_API_KEY":   "key",
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
				GitHubToken:  "ghp_x",
				GitHubAPIURL: "https://api.github.com",
				DTBaseURL:    "http://dt.example:8080",
				DTAPIKey:     "key",
				Port:         "8080",
			},
		},
		{
			name: "all set",
			env: map[string]string{
				"GITHUB_REPO":       "myorg/myrepo",
				"GITHUB_API_URL":    "https://ghe.example/api/v3",
				"DT_WEBHOOK_SECRET": "s3cr3t",
				"PORT":              "9090",
				"LOG_LEVEL":         "DEBUG",
			},
			want: Config{
				GitHubToken:   "ghp_x",
				GitHubRepo:    "myorg/myrepo",
				GitHubAPIURL:  "https://ghe.example/api/v3",
				DTBaseURL:     "http://dt.example:8080",
				DTAPIKey:      "key",
				WebhookSecret: "s3cr3t",
				Port:          "9090",
				LogLevel:      slog.LevelDebug,
			},
		},
		{name: "missing GitHub token", env: map[string]string{"GITHUB_TOKEN": ""}, wantErr: "GITHUB_TOKEN"},
		{name: "missing DT base URL", env: map[string]string{"DT_BASE_URL": ""}, wantErr: "DT_BASE_URL"},
		{name: "invalid DT base URL", env: map[string]string{"DT_BASE_URL": "dt.example"}, wantErr: "DT_BASE_URL"},
		{name: "missing DT API key", env: map[string]string{"DT_API_KEY": ""}, wantErr: "DT_API_KEY"},
		{name: "invalid fallback repo", env: map[string]string{"GITHUB_REPO": "not a repo"}, wantErr: "GITHUB_REPO"},
		{name: "invalid GitHub API URL", env: map[string]string{"GITHUB_API_URL": "api.github.com"}, wantErr: "GITHUB_API_URL"},
		{name: "invalid log level", env: map[string]string{"LOG_LEVEL": "verbose"}, wantErr: "LOG_LEVEL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel
			for _, k := range []string{"GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_API_URL", "DT_BASE_URL", "DT_API_KEY", "DT_WEBHOOK_SECRET", "PORT", "LOG_LEVEL"} {
				t.Setenv(k, valid[k])
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			got, err := FromEnv()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("FromEnv() error = %v, want error mentioning %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromEnv() unexpected error = %v", err)
			}
			if got != tc.want {
				t.Errorf("FromEnv() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
