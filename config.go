package main

import (
	"errors"
	"os"
)

type config struct {
	GitHubToken string
	GitHubRepo  string // optional fallback, e.g. "myorg/myrepo"
	DTBaseURL   string // Dependency-Track API base URL
	DTAPIKey    string // DT API key (read-only: VIEW_PORTFOLIO is sufficient)
	Port        string
}

func configFromEnv() (config, error) {
	cfg := config{
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		GitHubRepo:  os.Getenv("GITHUB_REPO"), // optional — inferred from project when absent
		DTBaseURL:   os.Getenv("DT_BASE_URL"),
		DTAPIKey:    os.Getenv("DT_API_KEY"),
		Port:        os.Getenv("PORT"),
	}

	if cfg.GitHubToken == "" {
		return config{}, errors.New("GITHUB_TOKEN env var is required")
	}
	if cfg.DTBaseURL == "" {
		return config{}, errors.New("DT_BASE_URL env var is required (e.g. http://dependency-track-apiserver.dependency-track.svc.cluster.local)")
	}
	if cfg.DTAPIKey == "" {
		return config{}, errors.New("DT_API_KEY env var is required")
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	return cfg, nil
}
