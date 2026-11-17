// Package config loads the service configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
)

type Config struct {
	GitHubToken  string
	GitHubRepo   string // optional fallback, e.g. "myorg/myrepo"
	GitHubAPIURL string // GitHub REST API base URL
	// AllowedRepos restricts the repositories issues may be created in.
	AllowedRepos *github.Allowlist
	// AllowPublicRepos permits creating issues in public repositories, which
	// discloses unfixed vulnerabilities.
	AllowPublicRepos bool
	// RepoSources are the project data repositories are resolved from.
	RepoSources []resolver.Source

	DTBaseURL     string // Dependency-Track API base URL
	DTAPIKey      string // DT API key (VIEW_PORTFOLIO + PORTFOLIO_MANAGEMENT_READ)
	WebhookSecret string // signing secret configured on the DT webhook alert
	// AllowUnsignedWebhooks permits running without WebhookSecret, accepting
	// notifications from anyone able to reach the service.
	AllowUnsignedWebhooks bool

	Port     string
	LogLevel slog.Level
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
		RepoSources:   resolver.AllSources,
	}

	if cfg.GitHubToken == "" {
		return Config{}, errors.New("GITHUB_TOKEN env var is required")
	}

	allowed := os.Getenv("GITHUB_ALLOWED_REPOS")
	if allowed == "" {
		return Config{}, errors.New(`GITHUB_ALLOWED_REPOS env var is required (e.g. "myorg/*" or "myorg/repo1,myorg/repo2")`)
	}
	var err error
	if cfg.AllowedRepos, err = github.NewAllowlist(strings.Split(allowed, ",")); err != nil {
		return Config{}, fmt.Errorf("GITHUB_ALLOWED_REPOS: %w", err)
	}

	if cfg.GitHubRepo != "" {
		if !github.IsValidRepo(cfg.GitHubRepo) {
			return Config{}, fmt.Errorf("GITHUB_REPO %q is not a valid \"owner/repo\"", cfg.GitHubRepo)
		}
		if !cfg.AllowedRepos.Allows(cfg.GitHubRepo) {
			return Config{}, fmt.Errorf("GITHUB_REPO %q is not allowed by GITHUB_ALLOWED_REPOS", cfg.GitHubRepo)
		}
	}

	if sources := os.Getenv("REPO_SOURCES"); sources != "" {
		if cfg.RepoSources, err = resolver.ParseSources(sources); err != nil {
			return Config{}, fmt.Errorf("REPO_SOURCES: %w", err)
		}
	}

	if cfg.GitHubAPIURL == "" {
		cfg.GitHubAPIURL = "https://api.github.com"
	}
	// The GitHub token is sent with every request.
	if u, err := url.Parse(cfg.GitHubAPIURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return Config{}, fmt.Errorf("GITHUB_API_URL %q is not a valid https URL", cfg.GitHubAPIURL)
	}

	if cfg.DTBaseURL == "" {
		return Config{}, errors.New("DT_BASE_URL env var is required (e.g. http://dependency-track-api-server.dependency-track.svc.cluster.local:8080)")
	}
	if u, err := url.ParseRequestURI(cfg.DTBaseURL); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Config{}, fmt.Errorf("DT_BASE_URL %q is not a valid http(s) URL", redactURL(cfg.DTBaseURL))
	}
	if cfg.DTAPIKey == "" {
		return Config{}, errors.New("DT_API_KEY env var is required")
	}

	if cfg.AllowUnsignedWebhooks, err = parseBool("ALLOW_UNSIGNED_WEBHOOKS"); err != nil {
		return Config{}, err
	}
	if cfg.WebhookSecret == "" && !cfg.AllowUnsignedWebhooks {
		return Config{}, errors.New("DT_WEBHOOK_SECRET env var is required (set ALLOW_UNSIGNED_WEBHOOKS=true to accept unsigned notifications)")
	}
	if cfg.AllowPublicRepos, err = parseBool("ALLOW_PUBLIC_REPOS"); err != nil {
		return Config{}, err
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

// RedactedDTBaseURL returns the Dependency-Track URL safe for logging.
func (c Config) RedactedDTBaseURL() string { return redactURL(c.DTBaseURL) }

// redactURL hides a password embedded in a URL.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(invalid URL)"
	}
	return u.Redacted()
}

func parseBool(name string) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s %q is not a boolean", name, v)
	}
	return b, nil
}
