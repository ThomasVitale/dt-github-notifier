// Command dt-github-notifier receives Dependency-Track webhook notifications
// and creates GitHub issues for policy violations and vulnerabilities.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	dtrack "github.com/DependencyTrack/client-go"

	"github.com/thomasvitale/dt-github-notifier/internal/config"
	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
	"github.com/thomasvitale/dt-github-notifier/internal/webhook"
)

// shutdownTimeout bounds how long in-flight requests may run after SIGTERM.
// It is above webhook.RequestTimeout so that started notifications can complete.
const shutdownTimeout = webhook.RequestTimeout + 2*time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("dt-github-notifier stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           newHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      webhook.RequestTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
	}

	if cfg.WebhookSecret == "" {
		slog.Warn("DT_WEBHOOK_SECRET is not set and ALLOW_UNSIGNED_WEBHOOKS=true: " +
			"anyone able to reach the service can make it create issues")
	}
	if cfg.AllowPublicRepos {
		slog.Warn("ALLOW_PUBLIC_REPOS=true: unfixed vulnerabilities can be disclosed in public repositories")
	}
	if strings.HasPrefix(cfg.DTBaseURL, "http://") {
		slog.Warn("DT_BASE_URL uses plain HTTP: the Dependency-Track API key is sent unencrypted")
	}
	slog.Info("starting dt-github-notifier",
		"port", cfg.Port,
		"dtBaseURL", cfg.RedactedDTBaseURL(),
		"gitHubAPIURL", cfg.GitHubAPIURL,
		"defaultRepo", cfg.GitHubRepo,
		"repoSources", cfg.RepoSources,
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

// newHandler wires the service components and routes.
func newHandler(cfg config.Config) http.Handler {
	newDTClient := func() (*dtrack.Client, error) {
		return dtrack.NewClient(cfg.DTBaseURL,
			dtrack.WithAPIKey(cfg.DTAPIKey),
			dtrack.WithUserAgent("dt-github-notifier"),
			// Below webhook.RequestTimeout, so that creating the client on the
			// first request still leaves time to process the notification.
			dtrack.WithTimeout(5*time.Second),
		)
	}

	repos := resolver.New(newDTClient, resolver.Options{
		DefaultRepo: cfg.GitHubRepo,
		Sources:     cfg.RepoSources,
		Allowed:     cfg.AllowedRepos.Allows,
	})
	issues := github.New(cfg.GitHubAPIURL, cfg.GitHubToken)

	mux := http.NewServeMux()
	mux.Handle("/webhook", webhook.New(issues, repos, webhook.Options{
		Secret:             cfg.WebhookSecret,
		AllowPublicRepos:   cfg.AllowPublicRepos,
		MaxNotificationAge: cfg.MaxNotificationAge,
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}
