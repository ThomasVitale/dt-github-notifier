package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
)

// shutdownTimeout bounds how long in-flight requests may run after SIGTERM.
// It is above requestTimeout so that started notifications can complete.
const shutdownTimeout = requestTimeout + 2*time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("dt-github-notifier stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}

	newDTClient := func() (*dtrack.Client, error) {
		return dtrack.NewClient(cfg.DTBaseURL,
			dtrack.WithAPIKey(cfg.DTAPIKey),
			dtrack.WithUserAgent("dt-github-notifier"),
			// Below requestTimeout, so that creating the client on the first
			// request still leaves time to process the notification.
			dtrack.WithTimeout(5*time.Second),
		)
	}

	resolver := newRepoResolver(newDTClient, cfg.GitHubRepo)
	ghClient := newGitHubClient(cfg.GitHubAPIURL, cfg.GitHubToken)
	handler := newWebhookHandler(ghClient, resolver, cfg.WebhookSecret)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", handler.handleWebhook)
	mux.HandleFunc("/healthz", handleHealthz)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      requestTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
	}

	if cfg.WebhookSecret == "" {
		slog.Warn("DT_WEBHOOK_SECRET is not set: webhook signatures are not verified")
	}
	slog.Info("starting dt-github-notifier",
		"port", cfg.Port,
		"dtBaseURL", cfg.DTBaseURL,
		"gitHubAPIURL", cfg.GitHubAPIURL,
		"defaultRepo", cfg.GitHubRepo,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down, draining in-flight requests")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-serverErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
