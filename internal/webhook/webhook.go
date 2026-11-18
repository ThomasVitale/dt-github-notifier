// Package webhook receives Dependency-Track notifications and turns them into
// GitHub issues, closing them again once the findings are resolved.
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

	// maxClockSkew is how far in the future a notification timestamp may be.
	maxClockSkew = 5 * time.Minute
)

var (
	// errUnhandledGroup is returned for notification groups that create no issue.
	errUnhandledGroup = errors.New("unhandled notification group")
	// errNothingToDo is returned for notifications that need no change, such as
	// an audit decision that leaves a finding open.
	errNothingToDo = errors.New("nothing to do")
	// errPublicRepo is returned when the resolved repo is public and public
	// repos are not allowed.
	errPublicRepo = errors.New("refusing to disclose vulnerability details in a public repository")
)

// IssueTracker finds, creates and closes GitHub issues.
type IssueTracker interface {
	// IsPublic reports whether the repo is publicly visible.
	IsPublic(ctx context.Context, repo string) (bool, error)
	// FindOpenIssue returns an open issue whose body contains key, or the
	// zero Ref when there is none.
	FindOpenIssue(ctx context.Context, repo, key string) (issue.Ref, error)
	// CreateIssue creates the issue.
	CreateIssue(ctx context.Context, repo string, i issue.Issue) (issue.Ref, error)
	// CloseIssue comments on the issue and closes it.
	CloseIssue(ctx context.Context, repo string, number int, c issue.Closure) error
}

// RepoResolver resolves the GitHub "owner/repo" of a Dependency-Track project.
type RepoResolver interface {
	Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error)
}

// Handler turns Dependency-Track notifications into GitHub issues:
//   - NEW_VULNERABILITY and POLICY_VIOLATION create an issue, unless an open
//     issue already tracks the same finding (see issue.Issue.Key).
//     NEW_VULNERABLE_DEPENDENCY is not handled: each of its vulnerabilities
//     also arrives as a NEW_VULNERABILITY notification.
//   - PROJECT_AUDIT_CHANGE and VULNERABILITY_RETRACTED close the open issue
//     about the finding, when the audit decision or retraction resolves it
//
// Response codes follow the retry semantics of the DT webhook publisher, which
// retries 429, 502, 503 and 504 and gives up on any other non-2xx status:
//   - 204 when the notification was handled, needs no change, or its group is
//     not handled
//   - 400 / 401 / 413 / 422 for requests that will never succeed (422 when no
//     repo can be resolved or it is public and public repos are not allowed)
//   - 500 for permanent failures (e.g. GitHub rejected the issue)
//   - 503 for transient failures (DT API or GitHub unavailable, rate limits)
type Handler struct {
	issues      IssueTracker
	repos       RepoResolver
	secret      []byte // empty when signature verification is disabled
	allowPublic bool
	maxAge      time.Duration // zero when notification age is not checked
	timeout     time.Duration
	now         func() time.Time

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
	// MaxNotificationAge, when not zero, rejects notifications whose ID (a
	// UUIDv7, which embeds its creation time) is older, limiting replays of
	// captured requests.
	MaxNotificationAge time.Duration
}

// New returns a Handler.
func New(issues IssueTracker, repos RepoResolver, opts Options) *Handler {
	return &Handler{
		issues:      issues,
		repos:       repos,
		secret:      []byte(opts.Secret),
		allowPublic: opts.AllowPublicRepos,
		maxAge:      opts.MaxNotificationAge,
		timeout:     RequestTimeout,
		now:         time.Now,
		recent:      newRecentIssues(recentIssuesTTL, recentIssuesMax),
	}
}

// action is what a notification asks for: creating or closing an issue.
type action struct {
	project notification.Project
	create  *issue.Issue
	close   *issue.Closure
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

	if h.maxAge > 0 {
		if err := checkAge(n.ID, h.now(), h.maxAge); err != nil {
			log.Warn("rejecting notification", "err", err, "remoteAddr", r.RemoteAddr)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}

	log.Info("received notification", "level", n.Level, "title", n.Title)

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	a, err := plan(n)
	switch {
	case errors.Is(err, errUnhandledGroup):
		log.Info("ignoring unhandled notification group")
		w.WriteHeader(http.StatusNoContent)
		return
	case errors.Is(err, errNothingToDo):
		log.Info("audit decision leaves the finding open, nothing to do")
		w.WriteHeader(http.StatusNoContent)
		return
	case err != nil:
		writeError(w, log, err)
		return
	}

	repo, err := h.resolve(ctx, a.project)
	if err != nil {
		writeError(w, log, err)
		return
	}
	log = log.With("repo", repo)

	if a.create != nil {
		ref, created, err := h.ensureIssue(ctx, repo, *a.create)
		switch {
		case err != nil:
			writeError(w, log.With("title", a.create.Title), err)
			return
		case created:
			log.Info("created GitHub issue", "title", a.create.Title, "url", ref.URL)
		default:
			log.Info("GitHub issue already exists, skipping", "key", a.create.Key, "url", ref.URL)
		}
	} else {
		ref, err := h.closeIssue(ctx, repo, *a.close)
		switch {
		case err != nil:
			writeError(w, log.With("key", a.close.Key), err)
			return
		case ref.Number == 0:
			log.Info("no open GitHub issue to close", "key", a.close.Key)
		default:
			log.Info("closed GitHub issue", "url", ref.URL, "reason", a.close.Reason)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// plan decodes the notification subject and decides the action to take.
func plan(n notification.Notification) (action, error) {
	switch n.Group {
	case notification.GroupPolicyViolation:
		s, err := notification.DecodeSubject[notification.PolicyViolationSubject](n)
		if err != nil {
			return action{}, err
		}
		i, err := issue.ForPolicyViolation(s)
		return action{project: s.Project, create: &i}, err
	case notification.GroupNewVulnerability:
		s, err := notification.DecodeSubject[notification.NewVulnerabilitySubject](n)
		if err != nil {
			return action{}, err
		}
		i, err := issue.ForNewVulnerability(s)
		return action{project: s.Project, create: &i}, err
	case notification.GroupProjectAuditChange:
		s, err := notification.DecodeSubject[notification.ProjectAuditChangeSubject](n)
		if err != nil {
			return action{}, err
		}
		c, ok := issue.ForProjectAuditChange(s)
		if !ok {
			return action{}, errNothingToDo
		}
		return action{project: s.Project, close: &c}, nil
	case notification.GroupVulnerabilityRetracted:
		s, err := notification.DecodeSubject[notification.VulnerabilityRetractedSubject](n)
		if err != nil {
			return action{}, err
		}
		c := issue.ForVulnerabilityRetracted(s)
		return action{project: s.Project, close: &c}, nil
	default:
		return action{}, errUnhandledGroup
	}
}

// resolve returns the repo of the project a notification concerns.
func (h *Handler) resolve(ctx context.Context, p notification.Project) (string, error) {
	projectUUID, err := uuid.Parse(p.UUID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid project UUID %q", notification.ErrInvalidPayload, p.UUID)
	}
	return h.repos.Resolve(ctx, projectUUID)
}

// ensureIssue creates the issue unless an open issue with the same key exists
// in the repo, and returns the created or existing issue.
func (h *Handler) ensureIssue(ctx context.Context, repo string, i issue.Issue) (issue.Ref, bool, error) {
	type result struct {
		ref     issue.Ref
		created bool
	}
	key := recentKey(repo, i.Key)
	v, err, _ := h.inflight.Do("create "+key, func() (any, error) {
		if ref, ok := h.recent.get(key); ok {
			return result{ref: ref}, nil
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
		ref, err := h.issues.FindOpenIssue(ctx, repo, i.Key)
		if err != nil {
			return nil, fmt.Errorf("search for existing issue: %w", err)
		}
		if ref.Number != 0 {
			h.recent.add(key, ref)
			return result{ref: ref}, nil
		}
		if ref, err = h.issues.CreateIssue(ctx, repo, i); err != nil {
			return nil, err
		}
		h.recent.add(key, ref)
		return result{ref: ref, created: true}, nil
	})
	if err != nil {
		return issue.Ref{}, false, err
	}
	r := v.(result)
	return r.ref, r.created, nil
}

// closeIssue closes the open issue with the closure's key, and returns it, or
// the zero Ref when there is no such issue.
func (h *Handler) closeIssue(ctx context.Context, repo string, c issue.Closure) (issue.Ref, error) {
	key := recentKey(repo, c.Key)
	v, err, _ := h.inflight.Do("close "+key, func() (any, error) {
		// An issue created moments ago may not be returned by search yet.
		ref, ok := h.recent.get(key)
		if !ok || ref.Number == 0 {
			var err error
			if ref, err = h.issues.FindOpenIssue(ctx, repo, c.Key); err != nil {
				return nil, fmt.Errorf("search for the issue to close: %w", err)
			}
			if ref.Number == 0 {
				return issue.Ref{}, nil
			}
		}
		if err := h.issues.CloseIssue(ctx, repo, ref.Number, c); err != nil {
			return nil, err
		}
		// A later notification about the same finding opens a new issue.
		h.recent.remove(key)
		return ref, nil
	})
	if err != nil {
		return issue.Ref{}, err
	}
	return v.(issue.Ref), nil
}

func recentKey(repo, issueKey string) string {
	return strings.ToLower(repo) + " " + issueKey
}

// checkAge verifies that the notification ID is a UUIDv7 created no more than
// maxAge ago (and not in the future, beyond maxClockSkew).
func checkAge(id string, now time.Time, maxAge time.Duration) error {
	u, err := uuid.Parse(id)
	if err != nil || u.Version() != 7 {
		return fmt.Errorf("notification ID %q is not a UUIDv7, so its age cannot be checked "+
			"(set MAX_NOTIFICATION_AGE=0 to disable the check)", id)
	}
	created := time.Unix(u.Time().UnixTime())
	switch age := now.Sub(created); {
	case age > maxAge:
		return fmt.Errorf("notification created at %s is older than %s, the maximum age", created.UTC().Format(time.RFC3339), maxAge)
	case age < -maxClockSkew:
		return fmt.Errorf("notification created at %s is in the future", created.UTC().Format(time.RFC3339))
	}
	return nil
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
		log.Error("failed to update GitHub issue", "err", err)
		http.Error(w, "failed to update issue", http.StatusInternalServerError)
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
