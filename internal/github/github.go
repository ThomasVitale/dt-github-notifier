// Package github creates and finds issues through the GitHub REST API.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thomasvitale/dt-github-notifier/internal/issue"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
)

const (
	// maxErrorBodyBytes bounds how much of a GitHub error response is read.
	maxErrorBodyBytes = 64 << 10
	// maxResponseBodyBytes bounds how much of a successful response is read.
	maxResponseBodyBytes = 1 << 20
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// issueRequest is the body of the "create an issue" endpoint.
type issueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

// New returns a client for the GitHub REST API at baseURL (e.g.
// https://api.github.com), authenticating with token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// CreateIssue creates an issue in the given "owner/repo" and returns its URL.
// Rate limiting, server errors and network failures are returned as retryable
// errors.
func (c *Client) CreateIssue(ctx context.Context, repo string, i issue.Issue) (string, error) {
	if !IsValidRepo(repo) {
		return "", fmt.Errorf("invalid GitHub repo %q", repo)
	}

	payload, err := json.Marshal(issueRequest{Title: i.Title, Body: i.Body, Labels: i.Labels})
	if err != nil {
		return "", fmt.Errorf("marshal issue: %w", err)
	}

	var created struct {
		HTMLURL string `json:"html_url"`
	}
	endpoint := fmt.Sprintf("%s/repos/%s/issues", c.baseURL, repo)
	if err := c.do(ctx, http.MethodPost, endpoint, payload, http.StatusCreated, &created); err != nil {
		return "", err
	}
	return created.HTMLURL, nil
}

// FindOpenIssue returns the URL of an open issue in the given "owner/repo"
// whose body contains key, or "" when there is none. It uses the search API,
// whose index can lag a few seconds behind newly created issues.
func (c *Client) FindOpenIssue(ctx context.Context, repo, key string) (string, error) {
	if !IsValidRepo(repo) {
		return "", fmt.Errorf("invalid GitHub repo %q", repo)
	}

	var result struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	query := fmt.Sprintf(`repo:%s is:issue is:open in:body "%s"`, repo, key)
	endpoint := fmt.Sprintf("%s/search/issues?per_page=1&q=%s", c.baseURL, url.QueryEscape(query))
	if err := c.do(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &result); err != nil {
		return "", err
	}
	if len(result.Items) == 0 {
		return "", nil
	}
	return result.Items[0].HTMLURL, nil
}

// do sends an API request and decodes the response into out when the status
// is wantStatus. Rate limiting, server errors and network failures are
// returned as retryable errors.
func (c *Client) do(ctx context.Context, method, endpoint string, payload []byte, wantStatus int, out any) error {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return retryable.Wrap(fmt.Errorf("%s %s: %w", method, req.URL.Path, err), 0)
	}
	defer resp.Body.Close()

	if resp.StatusCode == wantStatus {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, req.URL.Path, err)
		}
		return nil
	}

	var ghErr struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodyBytes)).Decode(&ghErr)
	err = fmt.Errorf("%s %s: GitHub API returned status %d: %s", method, req.URL.Path, resp.StatusCode, ghErr.Message)

	if isRateLimited(resp, ghErr.Message) || resp.StatusCode >= http.StatusInternalServerError {
		return retryable.Wrap(err, retryAfter(resp.Header, time.Now()))
	}
	return err
}

// isRateLimited reports whether GitHub rejected the request because of its
// primary or secondary rate limits.
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
func isRateLimited(resp *http.Response, message string) bool {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusForbidden:
		return resp.Header.Get("X-Ratelimit-Remaining") == "0" ||
			resp.Header.Get("Retry-After") != "" ||
			strings.Contains(strings.ToLower(message), "rate limit")
	default:
		return false
	}
}

// retryAfter returns how long GitHub asks clients to wait, based on the
// Retry-After or X-RateLimit-Reset headers, or zero when neither is set.
func retryAfter(h http.Header, now time.Time) time.Duration {
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	if h.Get("X-Ratelimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(h.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
			if d := time.Unix(reset, 0).Sub(now); d > 0 {
				return d
			}
		}
	}
	return 0
}

// repoPattern matches a GitHub "owner/repo": owners are alphanumeric with
// hyphens, repo names may also contain dots and underscores.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// IsValidRepo reports whether repo is a well-formed GitHub "owner/repo".
func IsValidRepo(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	name := repo[strings.IndexByte(repo, '/')+1:]
	return name != "." && name != ".."
}
