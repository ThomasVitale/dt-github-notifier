package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

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
type dtClientAdapter struct {
	c *dtrack.Client
}

func (a *dtClientAdapter) getProject(ctx context.Context, id uuid.UUID) (dtrack.Project, error) {
	return a.c.Project.Get(ctx, id)
}

func (a *dtClientAdapter) getProperties(ctx context.Context, id uuid.UUID) ([]dtrack.ProjectProperty, error) {
	page, err := a.c.ProjectProperty.GetAll(ctx, id, dtrack.PageOptions{PageSize: 100})
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

func newRepoResolver(dt *dtrack.Client, defaultRepo string) *repoResolver {
	return &repoResolver{dt: &dtClientAdapter{c: dt}, defaultRepo: defaultRepo}
}

// Resolve returns the GitHub "org/repo" for the given DT project UUID.
// It never returns an empty string: if all lookups fail it returns defaultRepo.
// It returns an error only when defaultRepo is also empty and nothing was found.
func (r *repoResolver) Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error) {
	project, err := r.dt.getProject(ctx, projectUUID)
	if err != nil {
		slog.Warn("could not fetch project from DT API, falling back to default repo",
			"projectUUID", projectUUID, "err", err)
		return r.fallback(projectUUID)
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
	if err == nil {
		for _, p := range props {
			if strings.EqualFold(p.Group, "github") && strings.EqualFold(p.Name, "repo") {
				repo := strings.TrimSpace(p.Value)
				if repo != "" {
					slog.Debug("resolved repo from project property",
						"project", project.Name, "repo", repo)
					return repo, nil
				}
			}
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
	return "", fmt.Errorf("no GitHub repo configured and could not infer one for project %s", projectUUID)
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
	org := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	if org == "" || repo == "" {
		return "", false
	}
	return org + "/" + repo, true
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
	// Drop version suffix after @
	rest = strings.SplitN(rest, "@", 2)[0]
	// Should now be "org/repo"
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[0] + "/" + parts[1], true
}
