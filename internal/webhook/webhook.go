// Package webhook receives Dependency-Track notifications and turns them into
// GitHub issues.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/thomasvitale/dt-github-notifier/internal/issue"
	"github.com/thomasvitale/dt-github-notifier/internal/notification"
	"github.com/thomasvitale/dt-github-notifier/internal/resolver"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
)

const (
	// maxRequestBodyBytes bounds the notification size, and with it the memory
	// a request can use before its signature is verified. Event notifications
	// are a few KiB; the large scheduled summaries come from separate alerts.
	maxRequestBodyBytes = 1 << 20

	// RequestTimeout bounds the processing of a notification. It must stay
	// below the 10 s Dependency-Track waits for a webhook response, otherwise
	// DT gives up and retries a notification that may have been processed.
	RequestTimeout = 8 * time.Second

	signatureHeader = "X-Webhook-Signature"

	// recentIssuesTTL is how long handled issues are remembered, covering the
	// lag of GitHub's search index; recentIssuesMax bounds the memory used.
	recentIssuesTTL = 15 * time.Minute
	recentIssuesMax = 10_000
)

var (
	// errUnhandledGroup is returned for notification groups that create no issue.
	errUnhandledGroup = errors.New("unhandled notification group")
	// errPublicRepo is returned when the resolved repo is public and public
	// repos are not allowed.
	errPublicRepo = errors.New("refusing to disclose vulnerability details in a public repository")
)

// IssueTracker finds and creates GitHub issues.
type IssueTracker interface {
	// IsPublic reports whether the repo is publicly visible.
	IsPublic(ctx context.Context, repo string) (bool, error)
	// FindOpenIssue returns the URL of an open issue whose body contains key,
	// or "" when there is none.
	FindOpenIssue(ctx context.Context, repo, key string) (string, error)
	// CreateIssue creates the issue and returns its URL.
	CreateIssue(ctx context.Context, repo string, i issue.Issue) (string, error)
}

// RepoResolver resolves the GitHub "owner/repo" of a Dependency-Track project.
type RepoResolver interface {
	Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error)
}

// Handler creates a GitHub issue for each Dependency-Track notification,
// unless an open issue already tracks the same finding (see issue.Issue.Key).
//
// Response codes follow the retry semantics of the DT webhook publisher, which
// retries 429, 502, 503 and 504 and gives up on any other non-2xx status:
//   - 204 when the issue was created or already exists, or the group is not handled
//   - 400 / 401 / 413 / 422 for requests that will never succeed (422 when no
//     repo can be resolved or it is public and public repos are not allowed)
//   - 500 for permanent failures (e.g. GitHub rejected the issue)
//   - 503 for transient failures (DT API or GitHub unavailable, rate limits)
type Handler struct {
	issues      IssueTracker
	repos       RepoResolver
	secret      []byte // empty when signature verification is disabled
	allowPublic bool
	timeout     time.Duration

	recent   *recentIssues
	inflight singleflight.Group // collapses concurrent notifications for the same issue
}

// Options configures a Handler.
type Options struct {
	// Secret is the signing secret of the Dependency-Track webhook alert. When
	// set, requests must carry a valid X-Webhook-Signature computed with it.
	Secret string
	// AllowPublicRepos permits creating issues in public repositories.
	AllowPublicRepos bool
}

// New returns a Handler.
func New(issues IssueTracker, repos RepoResolver, opts Options) *Handler {
	return &Handler{
		issues:      issues,
		repos:       repos,
		secret:      []byte(opts.Secret),
		allowPublic: opts.AllowPublicRepos,
		timeout:     RequestTimeout,
		recent:      newRecentIssues(recentIssuesTTL, recentIssuesMax),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			slog.Warn("notification body too large", "limit", maxBytesErr.Limit)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		slog.Error("failed to read notification body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(h.secret) > 0 && !validSignature(h.secret, body, r.Header.Get(signatureHeader)) {
		slog.Warn("rejecting notification with missing or invalid signature", "remoteAddr", r.RemoteAddr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	n, err := notification.Parse(body)
	if err != nil {
		slog.Error("failed to parse notification body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log := slog.With("notificationId", n.ID, "group", n.Group)
	log.Info("received notification", "level", n.Level, "title", n.Title)

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	repo, i, err := h.buildIssue(ctx, n)
	if errors.Is(err, errUnhandledGroup) {
		log.Info("ignoring unhandled notification group")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var (
		url     string
		created bool
	)
	if err == nil {
		url, created, err = h.ensureIssue(ctx, repo, i)
	}
	if err != nil {
		writeError(w, log.With("repo", repo, "title", i.Title), err)
		return
	}

	if created {
		log.Info("created GitHub issue", "repo", repo, "title", i.Title, "url", url)
	} else {
		log.Info("GitHub issue already exists, skipping", "repo", repo, "key", i.Key, "url", url)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ensureIssue creates the issue unless an open issue with the same key exists
// in the repo, and returns the URL of the created or existing issue.
func (h *Handler) ensureIssue(ctx context.Context, repo string, i issue.Issue) (string, bool, error) {
	type result struct {
		url     string
		created bool
	}
	key := repo + " " + i.Key
	v, err, _ := h.inflight.Do(key, func() (any, error) {
		if url, ok := h.recent.get(key); ok {
			return result{url: url}, nil
		}
		if !h.allowPublic {
			public, err := h.issues.IsPublic(ctx, repo)
			if err != nil {
				return nil, fmt.Errorf("check repository visibility: %w", err)
			}
			if public {
				return nil, errPublicRepo
			}
		}
		url, err := h.issues.FindOpenIssue(ctx, repo, i.Key)
		if err != nil {
			return nil, fmt.Errorf("search for existing issue: %w", err)
		}
		if url != "" {
			h.recent.add(key, url)
			return result{url: url}, nil
		}
		if url, err = h.issues.CreateIssue(ctx, repo, i); err != nil {
			return nil, err
		}
		h.recent.add(key, url)
		return result{url: url, created: true}, nil
	})
	if err != nil {
		return "", false, err
	}
	r := v.(result)
	return r.url, r.created, nil
}

// buildIssue builds the issue for a notification and resolves the repo of
// the project it concerns.
func (h *Handler) buildIssue(ctx context.Context, n notification.Notification) (string, issue.Issue, error) {
	var (
		p   notification.Project
		i   issue.Issue
		err error
	)
	switch n.Group {
	case notification.GroupPolicyViolation:
		var s notification.PolicyViolationSubject
		if s, err = notification.DecodeSubject[notification.PolicyViolationSubject](n); err == nil {
			p = s.Project
			i, err = issue.ForPolicyViolation(s)
		}
	case notification.GroupNewVulnerability:
		var s notification.NewVulnerabilitySubject
		if s, err = notification.DecodeSubject[notification.NewVulnerabilitySubject](n); err == nil {
			p = s.Project
			i, err = issue.ForNewVulnerability(s)
		}
	case notification.GroupNewVulnerableDependency:
		var s notification.NewVulnerableDependencySubject
		if s, err = notification.DecodeSubject[notification.NewVulnerableDependencySubject](n); err == nil {
			p = s.Project
			i, err = issue.ForNewVulnerableDependency(s)
		}
	default:
		return "", i, errUnhandledGroup
	}
	if err != nil {
		return "", i, err
	}

	projectUUID, err := uuid.Parse(p.UUID)
	if err != nil {
		return "", i, fmt.Errorf("%w: invalid project UUID %q", notification.ErrInvalidPayload, p.UUID)
	}
	repo, err := h.repos.Resolve(ctx, projectUUID)
	return repo, i, err
}

// writeError maps a processing error to the response status that makes
// Dependency-Track retry transient failures only.
func writeError(w http.ResponseWriter, log *slog.Logger, err error) {
	if after, ok := retryable.As(err); ok {
		log.Warn("transient failure, asking Dependency-Track to retry", "err", err)
		if after > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(after.Seconds()))))
		}
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case errors.Is(err, notification.ErrInvalidPayload):
		log.Error("invalid notification", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
	case errors.Is(err, resolver.ErrNoRepo):
		log.Error("cannot route notification to a GitHub repo", "err", err)
		http.Error(w, "no GitHub repo for project", http.StatusUnprocessableEntity)
	case errors.Is(err, errPublicRepo):
		log.Error("not creating issue: the repository is public (set ALLOW_PUBLIC_REPOS=true to allow it)", "err", err)
		http.Error(w, "repository is public", http.StatusUnprocessableEntity)
	default:
		log.Error("failed to create GitHub issue", "err", err)
		http.Error(w, "failed to create issue", http.StatusInternalServerError)
	}
}

// validSignature verifies the X-Webhook-Signature header sent by
// Dependency-Track: "sha256=" followed by the hex-encoded HMAC-SHA256 of the
// raw request body, keyed with the signing secret.
func validSignature(secret, body []byte, header string) bool {
	encoded, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	signature, err := hex.DecodeString(encoded)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(signature, mac.Sum(nil))
}
