package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
)


func main() {
	cfg, err := configFromEnv()
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	dtClient, err := dtrack.NewClient(cfg.DTBaseURL, dtrack.WithAPIKey(cfg.DTAPIKey))
	if err != nil {
		slog.Error("failed to create Dependency-Track client", "err", err)
		os.Exit(1)
	}

	resolver := newRepoResolver(dtClient, cfg.GitHubRepo)
	ghClient := newGitHubClient(cfg.GitHubToken)
	handler := newWebhookHandler(ghClient, resolver)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", handler.handleWebhook)
	mux.HandleFunc("/healthz", handleHealthz)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	slog.Info("starting dt-github-notifier",
		"port", cfg.Port,
		"dtBaseURL", cfg.DTBaseURL,
		"defaultRepo", cfg.GitHubRepo,
	)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
