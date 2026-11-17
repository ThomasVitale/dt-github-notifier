// Package resolver resolves the GitHub repository of a Dependency-Track project.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"

	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
)

// ErrNoRepo is returned when no GitHub repo could be resolved for a project
// and no fallback repo is configured.
var ErrNoRepo = errors.New("no GitHub repo could be resolved")

const (
	// cacheTTL is how long a resolved repo is reused, sparing Dependency-Track
	// a lookup for each of the many notifications a BOM upload can trigger.
	cacheTTL = 5 * time.Minute
	// cacheMax bounds the number of cached projects.
	cacheMax = 10_000
	// maxParentDepth bounds how many ancestors are searched for a repo, which
	// also guards against cycles in the project hierarchy.
	maxParentDepth = 5
)

// projectFetcher is the subset of the DT API used by Resolver.
// It is implemented by dtClientAdapter and faked in tests.
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

// Resolver resolves a GitHub "org/repo" string from a Dependency-Track project.
//
// Resolution is attempted in this order, limited to the configured sources:
//  1. Project external reference of type "vcs" pointing to github.com
//  2. Project property  group="github" name="repo"  value="org/repo"
//  3. Project PURL     pkg:github/org/repo@version
//  4. The same, recursively, on the parent project
//  5. Fallback to the statically configured default repo
//
// Repos that are not allowed are skipped. Resolved repos are cached for cacheTTL.
type Resolver struct {
	dt          projectFetcher
	defaultRepo string // fallback, may be empty
	sources     []Source
	allowed     func(repo string) bool

	mu    sync.Mutex
	cache map[uuid.UUID]cachedRepo
	now   func() time.Time
}

type cachedRepo struct {
	repo    string
	expires time.Time
}

// Options configures a Resolver.
type Options struct {
	// DefaultRepo is the fallback repo; it may be empty.
	DefaultRepo string
	// Sources are the project data consulted, in order; empty means AllSources.
	Sources []Source
	// Allowed reports whether a repo may be used. It is required.
	Allowed func(repo string) bool
}

// New returns a Resolver querying the Dependency-Track client returned by
// newClient, which is called on first use (and again until it succeeds).
func New(newClient func() (*dtrack.Client, error), opts Options) *Resolver {
	return newResolver(&dtClientAdapter{newClient: newClient}, opts)
}

func newResolver(dt projectFetcher, opts Options) *Resolver {
	if opts.Allowed == nil {
		panic("resolver: Options.Allowed is required")
	}
	if len(opts.Sources) == 0 {
		opts.Sources = AllSources
	}
	return &Resolver{
		dt:          dt,
		defaultRepo: opts.DefaultRepo,
		sources:     opts.Sources,
		allowed:     opts.Allowed,
		cache:       make(map[uuid.UUID]cachedRepo),
		now:         time.Now,
	}
}

// Resolve returns the GitHub "org/repo" for the given DT project UUID.
//
// It falls back to defaultRepo only when Dependency-Track answered and neither
// the project nor its ancestors carry a GitHub hint (or the project no longer
// exists), and returns ErrNoRepo when defaultRepo is empty too. Transient DT
// API failures are returned as retryable errors rather than routed to the
// fallback repo.
func (r *Resolver) Resolve(ctx context.Context, projectUUID uuid.UUID) (string, error) {
	if repo, ok := r.cached(projectUUID); ok {
		return repo, nil
	}
	repo, err := r.resolve(ctx, projectUUID, projectUUID, 0)
	if err != nil {
		return "", err
	}
	r.store(projectUUID, repo)
	return repo, nil
}

// resolve looks for a GitHub hint on projectUUID, which is the notified
// project or, at depth > 0, one of its ancestors.
func (r *Resolver) resolve(ctx context.Context, notified, projectUUID uuid.UUID, depth int) (string, error) {
	project, err := r.dt.getProject(ctx, projectUUID)
	switch {
	case err == nil:
	case apiStatus(err) == http.StatusNotFound:
		slog.Warn("project not found in DT, falling back to default repo", "projectUUID", projectUUID)
		return r.fallback(notified)
	case apiStatus(err) == http.StatusUnauthorized || apiStatus(err) == http.StatusForbidden:
		return "", fmt.Errorf("fetch project %s: DT API key lacks VIEW_PORTFOLIO or access to the project: %w", projectUUID, err)
	default:
		return "", retryable.Wrap(fmt.Errorf("fetch project %s: %w", projectUUID, err), 0)
	}

	for _, source := range r.sources {
		repo, err := r.fromSource(ctx, source, projectUUID, project)
		if err != nil {
			return "", err
		}
		if repo == "" {
			continue
		}
		if !r.allowed(repo) {
			slog.Warn("ignoring repo not allowed by GITHUB_ALLOWED_REPOS",
				"project", project.Name, "source", source, "repo", repo)
			continue
		}
		slog.Debug("resolved repo", "project", project.Name, "source", source, "repo", repo)
		return repo, nil
	}

	// No usable hint: try the parent project
	if parent := project.ParentRef; parent != nil && parent.UUID != uuid.Nil {
		if depth < maxParentDepth {
			slog.Debug("no GitHub hint on project, trying its parent",
				"project", project.Name, "parentUUID", parent.UUID)
			return r.resolve(ctx, notified, parent.UUID, depth+1)
		}
		slog.Warn("project hierarchy too deep, not searching further ancestors",
			"project", project.Name, "maxDepth", maxParentDepth)
	}

	slog.Warn("could not infer GitHub repo from project, falling back to default",
		"project", project.Name, "projectUUID", notified)
	return r.fallback(notified)
}

// fromSource returns the repo the given source designates for the project,
// or "" when it designates none.
func (r *Resolver) fromSource(ctx context.Context, source Source, projectUUID uuid.UUID, project dtrack.Project) (string, error) {
	switch source {
	case SourceVCS:
		for _, ref := range project.ExternalReferences {
			if strings.EqualFold(ref.Type, "vcs") {
				if repo, ok := repoFromURL(ref.URL); ok {
					return repo, nil
				}
			}
		}
	case SourceProperty:
		props, err := r.dt.getProperties(ctx, projectUUID)
		switch {
		case err == nil:
		case apiStatus(err) == http.StatusUnauthorized || apiStatus(err) == http.StatusForbidden:
			slog.Warn("cannot read project properties: DT API key lacks PORTFOLIO_MANAGEMENT_READ, skipping",
				"project", project.Name, "err", err)
		case apiStatus(err) == http.StatusNotFound:
		default:
			return "", retryable.Wrap(fmt.Errorf("fetch properties of project %s: %w", projectUUID, err), 0)
		}
		for _, p := range props {
			if strings.EqualFold(p.Group, "github") && strings.EqualFold(p.Name, "repo") {
				repo := strings.TrimSpace(p.Value)
				if github.IsValidRepo(repo) {
					return repo, nil
				}
				slog.Warn("ignoring invalid github/repo project property",
					"project", project.Name, "value", repo)
			}
		}
	case SourcePURL:
		if repo, ok := repoFromPURL(project.PURL); ok {
			return repo, nil
		}
	}
	return "", nil
}

func (r *Resolver) cached(projectUUID uuid.UUID) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.cache[projectUUID]
	if !ok || r.now().After(c.expires) {
		return "", false
	}
	return c.repo, true
}

// store caches the repo of a project. When full, it evicts expired entries
// first and then arbitrary ones, bounding memory use.
func (r *Resolver) store(projectUUID uuid.UUID, repo string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.cache) >= cacheMax {
		for k, c := range r.cache {
			if now.After(c.expires) {
				delete(r.cache, k)
			}
		}
	}
	for k := range r.cache {
		if len(r.cache) < cacheMax {
			break
		}
		delete(r.cache, k)
	}
	r.cache[projectUUID] = cachedRepo{repo: repo, expires: now.Add(cacheTTL)}
}

func (r *Resolver) fallback(projectUUID uuid.UUID) (string, error) {
	if r.defaultRepo != "" {
		return r.defaultRepo, nil
	}
	return "", fmt.Errorf("%w for project %s and GITHUB_REPO is not set", ErrNoRepo, projectUUID)
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
	return repo, github.IsValidRepo(repo)
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
	return rest, github.IsValidRepo(rest)
}
