// Package config loads the service configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/thomasvitale/dt-github-notifier/internal/github"
)

type Config struct {
	GitHubToken   string
	GitHubRepo    string // optional fallback, e.g. "myorg/myrepo"
	GitHubAPIURL  string // GitHub REST API base URL
	DTBaseURL     string // Dependency-Track API base URL
	DTAPIKey      string // DT API key (VIEW_PORTFOLIO + PORTFOLIO_MANAGEMENT_READ)
	WebhookSecret string // optional signing secret configured on the DT webhook alert
	Port          string
	LogLevel      slog.Level
}

func FromEnv() (Config, error) {
	cfg := Config{
		GitHubToken:   os.Getenv("GITHUB_TOKEN"),
		GitHubRepo:    os.Getenv("GITHUB_REPO"), // optional — inferred from project when absent
		GitHubAPIURL:  os.Getenv("GITHUB_API_URL"),
		DTBaseURL:     os.Getenv("DT_BASE_URL"),
		DTAPIKey:      os.Getenv("DT_API_KEY"),
		WebhookSecret: os.Getenv("DT_WEBHOOK_SECRET"),
		Port:          os.Getenv("PORT"),
	}

	if cfg.GitHubToken == "" {
		return Config{}, errors.New("GITHUB_TOKEN env var is required")
	}
	if cfg.GitHubRepo != "" && !github.IsValidRepo(cfg.GitHubRepo) {
		return Config{}, fmt.Errorf("GITHUB_REPO %q is not a valid \"owner/repo\"", cfg.GitHubRepo)
	}
	if cfg.GitHubAPIURL == "" {
		cfg.GitHubAPIURL = "https://api.github.com"
	}
	if u, err := url.Parse(cfg.GitHubAPIURL); err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, fmt.Errorf("GITHUB_API_URL %q is not a valid URL", cfg.GitHubAPIURL)
	}
	if cfg.DTBaseURL == "" {
		return Config{}, errors.New("DT_BASE_URL env var is required (e.g. http://dependency-track-api-server.dependency-track.svc.cluster.local:8080)")
	}
	if u, err := url.ParseRequestURI(cfg.DTBaseURL); err != nil || u.Host == "" {
		return Config{}, fmt.Errorf("DT_BASE_URL %q is not a valid URL", cfg.DTBaseURL)
	}
	if cfg.DTAPIKey == "" {
		return Config{}, errors.New("DT_API_KEY env var is required")
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(level)); err != nil {
			return Config{}, fmt.Errorf("LOG_LEVEL %q is not one of debug, info, warn, error", level)
		}
	}

	return cfg, nil
}
