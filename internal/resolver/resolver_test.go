package resolver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"

	"github.com/thomasvitale/dt-github-notifier/internal/github"
	"github.com/thomasvitale/dt-github-notifier/internal/retryable"
)

// ── fake projectFetcher ───────────────────────────────────────────────────────

type fakeProjectFetcher struct {
	project    dtrack.Project
	properties []dtrack.ProjectProperty
	projectErr error
	propsErr   error

	// projects, when set, serves projects by UUID instead of project
	// (unknown UUIDs get a 404).
	projects map[uuid.UUID]dtrack.Project

	projectCalls atomic.Int32
}

func (f *fakeProjectFetcher) getProject(_ context.Context, id uuid.UUID) (dtrack.Project, error) {
	f.projectCalls.Add(1)
	if f.projects != nil {
		p, ok := f.projects[id]
		if !ok {
			return dtrack.Project{}, &dtrack.APIError{StatusCode: http.StatusNotFound}
		}
		return p, nil
	}
	return f.project, f.projectErr
}

func (f *fakeProjectFetcher) getProperties(_ context.Context, _ uuid.UUID) ([]dtrack.ProjectProperty, error) {
	return f.properties, f.propsErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestResolver(fetcher projectFetcher, defaultRepo string) *Resolver {
	return newResolver(fetcher, Options{DefaultRepo: defaultRepo, Allowed: allowAll})
}

func allowAll(string) bool { return true }

// ── repoFromURL ───────────────────────────────────────────────────────────────

func TestRepoFromURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		url    string
		want   string
		wantOK bool
	}{
		{
			name:   "https with path",
			url:    "https://github.com/myorg/myrepo",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "https with .git suffix",
			url:    "https://github.com/myorg/myrepo.git",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "ssh url — not supported, ignored",
			url:    "git@github.com:myorg/myrepo.git",
			wantOK: false,
		},
		{
			name:   "gitlab url — not github",
			url:    "https://gitlab.com/myorg/myrepo",
			wantOK: false,
		},
		{
			name:   "github url with only org — no repo",
			url:    "https://github.com/myorg",
			wantOK: false,
		},
		{
			name:   "empty url",
			url:    "",
			wantOK: false,
		},
		{
			name:   "trailing slash preserved org/repo",
			url:    "https://github.com/myorg/myrepo/",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "deep path — only first two segments used",
			url:    "https://github.com/myorg/myrepo/tree/main",
			want:   "myorg/myrepo",
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := repoFromURL(tc.url)
			if ok != tc.wantOK {
				t.Errorf("repoFromURL(%q) ok = %v, want %v", tc.url, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("repoFromURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

// ── repoFromPURL ──────────────────────────────────────────────────────────────

func TestRepoFromPURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		purl   string
		want   string
		wantOK bool
	}{
		{
			name:   "standard github purl with version",
			purl:   "pkg:github/myorg/myrepo@1.0.0",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "github purl without version",
			purl:   "pkg:github/myorg/myrepo",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "maven purl — not github",
			purl:   "pkg:maven/org.apache/commons-lang3@3.12.0",
			wantOK: false,
		},
		{
			name:   "npm purl — not github",
			purl:   "pkg:npm/lodash@4.17.21",
			wantOK: false,
		},
		{
			name:   "empty purl",
			purl:   "",
			wantOK: false,
		},
		{
			name:   "malformed — no repo segment",
			purl:   "pkg:github/myorg",
			wantOK: false,
		},
		{
			name:   "qualifiers and subpath are dropped",
			purl:   "pkg:github/myorg/myrepo?arch=amd64#sub/dir",
			want:   "myorg/myrepo",
			wantOK: true,
		},
		{
			name:   "path traversal is rejected",
			purl:   "pkg:github/myorg/..@1.0.0",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := repoFromPURL(tc.purl)
			if ok != tc.wantOK {
				t.Errorf("repoFromPURL(%q) ok = %v, want %v", tc.purl, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("repoFromPURL(%q) = %q, want %q", tc.purl, got, tc.want)
			}
		})
	}
}

// ── Resolve ───────────────────────────────────────────────────────────────────

func TestResolve(t *testing.T) {
	t.Parallel()

	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	forbidden := &dtrack.APIError{StatusCode: http.StatusForbidden}

	tests := []struct {
		name        string
		fetcher     *fakeProjectFetcher
		defaultRepo string
		wantRepo    string
		wantErr     error // checked with errors.Is
		wantRetry   bool  // error must be retryable
	}{
		{
			name: "resolves from vcs external reference",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					ExternalReferences: []dtrack.ExternalReference{
						{Type: "vcs", URL: "https://github.com/myorg/my-service"},
					},
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "vcs ref with .git suffix is stripped",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					ExternalReferences: []dtrack.ExternalReference{
						{Type: "vcs", URL: "https://github.com/myorg/my-service.git"},
					},
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "non-github vcs ref falls through to property",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					ExternalReferences: []dtrack.ExternalReference{
						{Type: "vcs", URL: "https://gitlab.com/myorg/my-service"},
					},
				},
				properties: []dtrack.ProjectProperty{
					{Group: "github", Name: "repo", Value: "myorg/my-service"},
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "resolves from project property",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{Name: "my-service"},
				properties: []dtrack.ProjectProperty{
					{Group: "github", Name: "repo", Value: "myorg/my-service"},
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "property lookup is case-insensitive",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{Name: "my-service"},
				properties: []dtrack.ProjectProperty{
					{Group: "GitHub", Name: "Repo", Value: "myorg/my-service"},
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "resolves from project PURL",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					PURL: "pkg:github/myorg/my-service@1.0.0",
				},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "falls back to default repo when nothing matches",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{Name: "my-service"},
			},
			defaultRepo: "myorg/fallback-repo",
			wantRepo:    "myorg/fallback-repo",
		},
		{
			name: "falls back to default repo when project is not found",
			fetcher: &fakeProjectFetcher{
				projectErr: &dtrack.APIError{StatusCode: http.StatusNotFound},
			},
			defaultRepo: "myorg/fallback-repo",
			wantRepo:    "myorg/fallback-repo",
		},
		{
			name: "transient DT API failure is retryable, not routed to default repo",
			fetcher: &fakeProjectFetcher{
				projectErr: errors.New("connection refused"),
			},
			defaultRepo: "myorg/fallback-repo",
			wantRetry:   true,
		},
		{
			name: "DT API server error is retryable",
			fetcher: &fakeProjectFetcher{
				projectErr: &dtrack.APIError{StatusCode: http.StatusBadGateway},
			},
			wantRetry: true,
		},
		{
			name: "forbidden project is a permanent error",
			fetcher: &fakeProjectFetcher{
				projectErr: forbidden,
			},
			defaultRepo: "myorg/fallback-repo",
			wantErr:     forbidden,
		},
		{
			name: "returns ErrNoRepo when nothing resolves and no default set",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{Name: "my-service"},
			},
			defaultRepo: "",
			wantErr:     ErrNoRepo,
		},
		{
			name: "vcs ref takes priority over property",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					ExternalReferences: []dtrack.ExternalReference{
						{Type: "vcs", URL: "https://github.com/myorg/from-vcs"},
					},
				},
				properties: []dtrack.ProjectProperty{
					{Group: "github", Name: "repo", Value: "myorg/from-property"},
				},
			},
			wantRepo: "myorg/from-vcs",
		},
		{
			name: "property takes priority over PURL",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					PURL: "pkg:github/myorg/from-purl@1.0.0",
				},
				properties: []dtrack.ProjectProperty{
					{Group: "github", Name: "repo", Value: "myorg/from-property"},
				},
			},
			wantRepo: "myorg/from-property",
		},
		{
			name: "forbidden properties fall through to PURL",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					PURL: "pkg:github/myorg/my-service@1.0.0",
				},
				propsErr: &dtrack.APIError{StatusCode: http.StatusForbidden},
			},
			wantRepo: "myorg/my-service",
		},
		{
			name: "transient properties failure is retryable",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					PURL: "pkg:github/myorg/my-service@1.0.0",
				},
				propsErr: errors.New("properties unavailable"),
			},
			wantRetry: true,
		},
		{
			name: "invalid property value is ignored",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{
					Name: "my-service",
					PURL: "pkg:github/myorg/from-purl@1.0.0",
				},
				properties: []dtrack.ProjectProperty{
					{Group: "github", Name: "repo", Value: "../../orgs/evil"},
				},
			},
			wantRepo: "myorg/from-purl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newTestResolver(tc.fetcher, tc.defaultRepo)
			got, err := r.Resolve(context.Background(), projectID)
			_, retry := retryable.As(err)
			switch {
			case tc.wantRetry:
				if !retry {
					t.Fatalf("Resolve() error = %v, want retryable error", err)
				}
			case tc.wantErr != nil:
				if retry {
					t.Fatalf("Resolve() error = %v is retryable, want permanent", err)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Resolve() error = %v, want %v", err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("Resolve() unexpected error = %v", err)
			case got != tc.wantRepo:
				t.Errorf("Resolve() = %q, want %q", got, tc.wantRepo)
			}
		})
	}
}

// ── allowlist and sources ─────────────────────────────────────────────────────

func TestResolveSkipsReposThatAreNotAllowed(t *testing.T) {
	t.Parallel()
	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	fetcher := &fakeProjectFetcher{
		project: dtrack.Project{
			Name: "my-service",
			// Set by a BOM upload, pointing at a repo outside the organization.
			ExternalReferences: []dtrack.ExternalReference{{Type: "vcs", URL: "https://github.com/attacker/repo"}},
			PURL:               "pkg:github/myorg/my-service@1.0.0",
		},
	}
	allowed := func(repo string) bool { return strings.HasPrefix(repo, "myorg/") }

	r := newResolver(fetcher, Options{Allowed: allowed})
	if repo, err := r.Resolve(t.Context(), projectID); err != nil || repo != "myorg/my-service" {
		t.Errorf("Resolve() = %q, %v, want the allowed repo from the PURL", repo, err)
	}

	fetcher.project.PURL = ""
	r = newResolver(fetcher, Options{Allowed: allowed})
	if _, err := r.Resolve(t.Context(), projectID); !errors.Is(err, ErrNoRepo) {
		t.Errorf("Resolve() error = %v, want ErrNoRepo when only a disallowed repo is designated", err)
	}
}

func TestResolveUsesOnlyConfiguredSources(t *testing.T) {
	t.Parallel()
	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	fetcher := &fakeProjectFetcher{
		project: dtrack.Project{
			Name:               "my-service",
			ExternalReferences: []dtrack.ExternalReference{{Type: "vcs", URL: "https://github.com/myorg/from-vcs"}},
			PURL:               "pkg:github/myorg/from-purl@1.0.0",
		},
		properties: []dtrack.ProjectProperty{{Group: "github", Name: "repo", Value: "myorg/from-property"}},
	}

	tests := []struct {
		sources []Source
		want    string
	}{
		{[]Source{SourceProperty}, "myorg/from-property"},
		{[]Source{SourcePURL, SourceVCS}, "myorg/from-purl"},
		{nil, "myorg/from-vcs"}, // all sources, in the default order
	}
	for _, tc := range tests {
		r := newResolver(fetcher, Options{Sources: tc.sources, Allowed: allowAll})
		if repo, err := r.Resolve(t.Context(), projectID); err != nil || repo != tc.want {
			t.Errorf("Resolve() with sources %v = %q, %v, want %q", tc.sources, repo, err, tc.want)
		}
	}
}

func TestParseSources(t *testing.T) {
	t.Parallel()
	got, err := ParseSources(" Property , vcs,property")
	if err != nil || !slices.Equal(got, []Source{SourceProperty, SourceVCS}) {
		t.Errorf("ParseSources() = %v, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "vcs,git"} {
		if _, err := ParseSources(bad); err == nil {
			t.Errorf("ParseSources(%q) succeeded, want an error", bad)
		}
	}
}

// ── parent projects ───────────────────────────────────────────────────────────

func TestResolveFromParentProjects(t *testing.T) {
	t.Parallel()
	child := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	parent := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	grandparent := uuid.MustParse("00000000-0000-0000-0000-000000000003")

	fetcher := &fakeProjectFetcher{projects: map[uuid.UUID]dtrack.Project{
		child:  {Name: "child", ParentRef: &dtrack.ParentRef{UUID: parent}},
		parent: {Name: "parent", ParentRef: &dtrack.ParentRef{UUID: grandparent}},
		grandparent: {Name: "grandparent", ExternalReferences: []dtrack.ExternalReference{
			{Type: "vcs", URL: "https://github.com/myorg/monorepo"},
		}},
	}}
	repo, err := newTestResolver(fetcher, "myorg/fallback").Resolve(t.Context(), child)
	if err != nil || repo != "myorg/monorepo" {
		t.Errorf("Resolve() = %q, %v, want myorg/monorepo from the grandparent", repo, err)
	}
}

func TestResolveStopsAtParentCycles(t *testing.T) {
	t.Parallel()
	a := uuid.MustParse("00000000-0000-0000-0000-00000000000a")
	b := uuid.MustParse("00000000-0000-0000-0000-00000000000b")
	fetcher := &fakeProjectFetcher{projects: map[uuid.UUID]dtrack.Project{
		a: {Name: "a", ParentRef: &dtrack.ParentRef{UUID: b}},
		b: {Name: "b", ParentRef: &dtrack.ParentRef{UUID: a}},
	}}

	repo, err := newTestResolver(fetcher, "myorg/fallback").Resolve(t.Context(), a)
	if err != nil || repo != "myorg/fallback" {
		t.Errorf("Resolve() = %q, %v, want the fallback repo", repo, err)
	}
	if n := fetcher.projectCalls.Load(); n != maxParentDepth+1 {
		t.Errorf("fetched %d projects, want %d", n, maxParentDepth+1)
	}
}

func TestResolveMissingParentFallsBack(t *testing.T) {
	t.Parallel()
	child := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	fetcher := &fakeProjectFetcher{projects: map[uuid.UUID]dtrack.Project{
		child: {Name: "child", ParentRef: &dtrack.ParentRef{UUID: uuid.MustParse("00000000-0000-0000-0000-0000000000ff")}},
	}}
	_, err := newTestResolver(fetcher, "").Resolve(t.Context(), child)
	if !errors.Is(err, ErrNoRepo) {
		t.Errorf("Resolve() error = %v, want ErrNoRepo", err)
	}
}

// ── cache ─────────────────────────────────────────────────────────────────────

func TestResolveCachesRepos(t *testing.T) {
	t.Parallel()
	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	fetcher := &fakeProjectFetcher{project: dtrack.Project{
		Name:               "my-service",
		ExternalReferences: []dtrack.ExternalReference{{Type: "vcs", URL: "https://github.com/myorg/my-service"}},
	}}
	r := newTestResolver(fetcher, "")
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }

	for range 3 {
		if repo, err := r.Resolve(t.Context(), projectID); err != nil || repo != "myorg/my-service" {
			t.Fatalf("Resolve() = %q, %v", repo, err)
		}
	}
	if n := fetcher.projectCalls.Load(); n != 1 {
		t.Errorf("fetched the project %d times, want 1 while cached", n)
	}

	now = now.Add(cacheTTL + time.Second)
	if _, err := r.Resolve(t.Context(), projectID); err != nil {
		t.Fatal(err)
	}
	if n := fetcher.projectCalls.Load(); n != 2 {
		t.Errorf("fetched the project %d times, want 2 after the cache expired", n)
	}
}

func TestResolveDoesNotCacheFailures(t *testing.T) {
	t.Parallel()
	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	fetcher := &fakeProjectFetcher{projectErr: errors.New("connection refused")}
	r := newTestResolver(fetcher, "")
	for range 2 {
		_, _ = r.Resolve(t.Context(), projectID)
	}
	if n := fetcher.projectCalls.Load(); n != 2 {
		t.Errorf("fetched the project %d times, want 2 (failures are not cached)", n)
	}
}

func TestCacheIsBounded(t *testing.T) {
	t.Parallel()
	r := newTestResolver(&fakeProjectFetcher{}, "")
	for range cacheMax + 10 {
		r.store(uuid.New(), "myorg/repo")
	}
	if n := len(r.cache); n > cacheMax {
		t.Errorf("cache holds %d entries, want at most %d", n, cacheMax)
	}
}

// ── dtClientAdapter ───────────────────────────────────────────────────────────

// newFakeDT starts a Dependency-Track API stub serving one project. Until
// available is set, /api/version fails like an unreachable DT would.
func newFakeDT(t *testing.T, projectID uuid.UUID, available *atomic.Bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"application":"Dependency-Track","version":"5.2.0"}`))
	})
	mux.HandleFunc("GET /api/v1/project/"+projectID.String(), func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"my-service","externalReferences":[{"type":"vcs","url":"https://github.com/myorg/my-service"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDTClientAdapterIsCreatedLazily(t *testing.T) {
	t.Parallel()
	projectID := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	var available atomic.Bool
	srv := newFakeDT(t, projectID, &available)

	var created atomic.Int32
	r := New(func() (*dtrack.Client, error) {
		created.Add(1)
		return dtrack.NewClient(srv.URL, dtrack.WithAPIKey("test-key"))
	}, Options{Allowed: allowAll})

	// DT unavailable: the failure is retryable and nothing is cached.
	_, err := r.Resolve(t.Context(), projectID)
	if _, retry := retryable.As(err); !retry {
		t.Fatalf("Resolve() with DT unavailable error = %v, want retryable error", err)
	}

	available.Store(true)
	for range 2 {
		repo, err := r.Resolve(t.Context(), projectID)
		if err != nil || repo != "myorg/my-service" {
			t.Fatalf("Resolve() = %q, %v, want myorg/my-service", repo, err)
		}
	}
	if n := created.Load(); n != 2 {
		t.Errorf("client created %d times, want 2 (one failed attempt, then reused)", n)
	}
}

// ── fuzzing ───────────────────────────────────────────────────────────────────

// Every repo extracted from untrusted DT data must be a valid "owner/repo",
// as it ends up in the GitHub API request path.

func FuzzRepoFromURL(f *testing.F) {
	for _, s := range []string{
		"https://github.com/myorg/myrepo",
		"https://github.com/myorg/myrepo.git",
		"https://github.com/myorg/myrepo/tree/main",
		"https://github.com/myorg/..",
		"git@github.com:myorg/myrepo.git",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if repo, ok := repoFromURL(s); ok && !github.IsValidRepo(repo) {
			t.Errorf("repoFromURL(%q) = %q, which is not a valid repo", s, repo)
		}
	})
}

func FuzzRepoFromPURL(f *testing.F) {
	for _, s := range []string{
		"pkg:github/myorg/myrepo@1.0.0",
		"pkg:github/myorg/myrepo?arch=amd64#sub",
		"pkg:github/myorg/..",
		"pkg:maven/org.apache/commons@1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if repo, ok := repoFromPURL(s); ok && !github.IsValidRepo(repo) {
			t.Errorf("repoFromPURL(%q) = %q, which is not a valid repo", s, repo)
		}
	})
}
