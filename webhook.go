package main

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
)

const (
	// maxRequestBodyBytes bounds the notification size. Groups that are not
	// handled (e.g. scheduled summaries) can be large but must still be read
	// in full to verify their signature.
	maxRequestBodyBytes = 10 << 20

	// requestTimeout bounds the processing of a notification. It must stay
	// below the 10 s Dependency-Track waits for a webhook response, otherwise
	// DT gives up and retries a notification that may have been processed.
	requestTimeout = 8 * time.Second

	signatureHeader = "X-Webhook-Signature"
)

// errUnhandledGroup is returned for notification groups that create no issue.
var errUnhandledGroup = errors.New("unhandled notification group")

type webhookHandler struct {
	gh       *gitHubClient
	resolver *repoResolver
	secret   []byte // empty when signature verification is disabled
	timeout  time.Duration
}

func newWebhookHandler(gh *gitHubClient, resolver *repoResolver, secret string) *webhookHandler {
	return &webhookHandler{gh: gh, resolver: resolver, secret: []byte(secret), timeout: requestTimeout}
}

// handleWebhook creates a GitHub issue for a Dependency-Track notification.
//
// Response codes follow the retry semantics of the DT webhook publisher, which
// retries 429, 502, 503 and 504 and gives up on any other non-2xx status:
//   - 204 when the issue was created or the group is not handled
//   - 400 / 401 / 413 / 422 for requests that will never succeed
//   - 500 for permanent failures (e.g. GitHub rejected the issue)
//   - 503 for transient failures (DT API or GitHub unavailable, rate limits)
func (h *webhookHandler) handleWebhook(w http.ResponseWriter, r *http.Request) {
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

	n, err := parseNotification(body)
	if err != nil {
		slog.Error("failed to parse notification body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log := slog.With("notificationId", n.ID, "group", n.Group)
	log.Info("received notification", "level", n.Level, "title", n.Title)

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	repo, issue, err := h.buildIssue(ctx, n)
	if errors.Is(err, errUnhandledGroup) {
		log.Info("ignoring unhandled notification group")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err == nil {
		err = h.gh.createIssue(ctx, repo, issue)
	}
	if err != nil {
		writeError(w, log.With("repo", repo, "title", issue.Title), err)
		return
	}

	log.Info("created GitHub issue", "repo", repo, "title", issue.Title)
	w.WriteHeader(http.StatusNoContent)
}

// buildIssue builds the issue for a notification and resolves the repo of
// the project it concerns.
func (h *webhookHandler) buildIssue(ctx context.Context, n notification) (string, gitHubIssueRequest, error) {
	var (
		p     project
		issue gitHubIssueRequest
	)
	switch n.Group {
	case groupPolicyViolation:
		s, err := decodeSubject[policyViolationSubject](n)
		if err != nil {
			return "", issue, err
		}
		p, issue = s.Project, buildPolicyViolationIssue(s)
	case groupNewVulnerability:
		s, err := decodeSubject[newVulnerabilitySubject](n)
		if err != nil {
			return "", issue, err
		}
		p, issue = s.Project, buildNewVulnerabilityIssue(s)
	case groupNewVulnerableDependency:
		s, err := decodeSubject[newVulnerableDependencySubject](n)
		if err != nil {
			return "", issue, err
		}
		p, issue = s.Project, buildNewVulnerableDependencyIssue(s)
	default:
		return "", issue, errUnhandledGroup
	}

	projectUUID, err := uuid.Parse(p.UUID)
	if err != nil {
		return "", issue, fmt.Errorf("%w: invalid project UUID %q", errInvalidPayload, p.UUID)
	}
	repo, err := h.resolver.Resolve(ctx, projectUUID)
	return repo, issue, err
}

// writeError maps a processing error to the response status that makes
// Dependency-Track retry transient failures only.
func writeError(w http.ResponseWriter, log *slog.Logger, err error) {
	var retryErr *retryableError
	switch {
	case errors.As(err, &retryErr):
		log.Warn("transient failure, asking Dependency-Track to retry", "err", err)
		if retryErr.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryErr.retryAfter.Seconds()))))
		}
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	case errors.Is(err, errInvalidPayload):
		log.Error("invalid notification", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
	case errors.Is(err, errNoRepo):
		log.Error("cannot route notification to a GitHub repo", "err", err)
		http.Error(w, "no GitHub repo for project", http.StatusUnprocessableEntity)
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
