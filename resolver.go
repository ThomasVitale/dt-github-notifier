package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
)

// projectFetcher is the subset of the DT client used by repoResolver.
// It is satisfied by *dtrack.Client and can be faked in tests.
type projectFetcher interface {
	getProject(ctx context.Context, id uuid.UUID) (dtrack.Project, error)
	getProperties(ctx context.Context, id uuid.UUID) ([]dtrack.ProjectProperty, error)
}

// dtClientAdapter wraps *dtrack.Client to satisfy projectFetcher.
//
// The client is created on first use rather than at startup: dtrack.NewClient
// queries the Dependency-Track version, and an unavailable DT must not prevent
// the service from starting. Until it succeeds, every call returns the
// creation error, which the resolver reports as retryable.
type dtClientAdapter struct {
	newClient func() (*dtrack.Client, error)

	mu sync.Mutex
	c  *dtrack.Client
}

func (a *dtClientAdapter) client() (*dtrack.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.c == nil {
		c, err := a.newClient()
		if err != nil {
			return nil, fmt.Errorf("create Dependency-Track client: %w", err)
		}
		a.c = c
	}
	return a.c, nil
}

func (a *dtClientAdapter) getProject(ctx context.Context, id uuid.UUID) (dtrack.Project, error) {
	c, err := a.client()
	if err != nil {
		return dtrack.Project{}, err
	}
	return c.Project.Get(ctx, id)
}

func (a *dtClientAdapter) getProperties(ctx context.Context, id uuid.UUID) ([]dtrack.ProjectProperty, error) {
	c, err := a.client()
	if err != nil {
		return nil, err
	}
	page, err := c.ProjectProperty.GetAll(ctx, id, dtrack.PageOptions{PageSize: 100})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// repoResolver resolves a GitHub "org/repo" string from a Dependency-Track project.
//
// Resolution is attempted in this order:
//  1. Project external reference of type "vcs" pointing to github.com
//  2. Project property  group="github" name="repo"  value="org/repo"
//  3. Project PURL     pkg:github/org/repo@version
//  4. Fallback to the statically configured default repo
type repoResolver struct {
	dt          projectFetcher
	defaultRepo string // fallback, may be empty
}

func newRepoResolver(newClient func() (*dtrack.Client, error), defaultRepo string) *repoResolver {
	return &repoResolver{dt: &dtClientAdapter{newClient: newClient}, defaultRepo: defaultRepo}
}

// Resolve returns the GitHub "org/repo" for the given DT project UUID.
//
// It falls back to defaultRepo only when Dependency-Track answered and the
// project carries no GitHub hint (or no longer exists), and returns errNoRepo
// when defaultRepo is empty too. Transient DT API failures are returned as
// retryable errors rather than routed to the fallback repo.
func (r *repoResolver) Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error) {
	project, err := r.dt.getProject(ctx, projectUUID)
	switch {
	case err == nil:
	case apiStatus(err) == http.StatusNotFound:
		slog.Warn("project not found in DT, falling back to default repo", "projectUUID", projectUUID)
		return r.fallback(projectUUID)
	case apiStatus(err) == http.StatusUnauthorized || apiStatus(err) == http.StatusForbidden:
		return "", fmt.Errorf("fetch project %s: DT API key lacks VIEW_PORTFOLIO or access to the project: %w", projectUUID, err)
	default:
		return "", retryable(fmt.Errorf("fetch project %s: %w", projectUUID, err), 0)
	}

	// 1. External references — look for a vcs ref pointing at github.com
	for _, ref := range project.ExternalReferences {
		if strings.EqualFold(ref.Type, "vcs") {
			if repo, ok := repoFromURL(ref.URL); ok {
				slog.Debug("resolved repo from external reference",
					"project", project.Name, "repo", repo)
				return repo, nil
			}
		}
	}

	// 2. Project property: groupName="github", propertyName="repo"
	props, err := r.dt.getProperties(ctx, projectUUID)
	switch {
	case err == nil:
	case apiStatus(err) == http.StatusUnauthorized || apiStatus(err) == http.StatusForbidden:
		slog.Warn("cannot read project properties: DT API key lacks PORTFOLIO_MANAGEMENT_READ, skipping",
			"project", project.Name, "err", err)
	case apiStatus(err) == http.StatusNotFound:
	default:
		return "", retryable(fmt.Errorf("fetch properties of project %s: %w", projectUUID, err), 0)
	}
	for _, p := range props {
		if strings.EqualFold(p.Group, "github") && strings.EqualFold(p.Name, "repo") {
			repo := strings.TrimSpace(p.Value)
			if isValidRepo(repo) {
				slog.Debug("resolved repo from project property",
					"project", project.Name, "repo", repo)
				return repo, nil
			}
			slog.Warn("ignoring invalid github/repo project property",
				"project", project.Name, "value", repo)
		}
	}

	// 3. PURL  pkg:github/org/repo@version  or  pkg:github/org/repo
	if project.PURL != "" {
		if repo, ok := repoFromPURL(project.PURL); ok {
			slog.Debug("resolved repo from project PURL",
				"project", project.Name, "repo", repo)
			return repo, nil
		}
	}

	slog.Warn("could not infer GitHub repo from project, falling back to default",
		"project", project.Name, "projectUUID", projectUUID)
	return r.fallback(projectUUID)
}

func (r *repoResolver) fallback(projectUUID uuid.UUID) (string, error) {
	if r.defaultRepo != "" {
		return r.defaultRepo, nil
	}
	return "", fmt.Errorf("%w for project %s and GITHUB_REPO is not set", errNoRepo, projectUUID)
}

// apiStatus returns the HTTP status of a DT API error, or 0 for other errors.
func apiStatus(err error) int {
	var apiErr *dtrack.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// repoFromURL extracts "org/repo" from a GitHub URL.
// Handles https://github.com/org/repo, https://github.com/org/repo.git, etc.
func repoFromURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(u.Host, "github.com") {
		return "", false
	}
	// path is like /org/repo or /org/repo.git
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", false
	}
	repo := parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
	return repo, isValidRepo(repo)
}

// repoFromPURL extracts "org/repo" from a pkg:github/org/repo PURL.
func repoFromPURL(purl string) (string, bool) {
	// PURLs look like: pkg:github/org/repo@version
	// Strip the "pkg:" prefix
	without := strings.TrimPrefix(purl, "pkg:")
	if !strings.HasPrefix(strings.ToLower(without), "github/") {
		return "", false
	}
	// Remove "github/"
	rest := without[len("github/"):]
	// Drop the version, qualifiers and subpath
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	// Should now be "org/repo"
	return rest, isValidRepo(rest)
}
