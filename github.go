package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type gitHubClient struct {
	token      string
	httpClient *http.Client
}

type gitHubIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

func newGitHubClient(token string) *gitHubClient {
	return &gitHubClient{
		token: token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// createIssue creates an issue in the given "org/repo".
func (c *gitHubClient) createIssue(ctx context.Context, repo string, issue gitHubIssueRequest) error {
	payload, err := json.Marshal(issue)
	if err != nil {
		return fmt.Errorf("marshal issue: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/issues", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var ghErr struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&ghErr)
		return fmt.Errorf("github API returned status %d: %s", resp.StatusCode, ghErr.Message)
	}

	return nil
}
