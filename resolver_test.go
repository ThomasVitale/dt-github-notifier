package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
)

// ── fake projectFetcher ───────────────────────────────────────────────────────

type fakeProjectFetcher struct {
	project    dtrack.Project
	properties []dtrack.ProjectProperty
	projectErr error
	propsErr   error
}

func (f *fakeProjectFetcher) getProject(_ context.Context, _ uuid.UUID) (dtrack.Project, error) {
	return f.project, f.projectErr
}

func (f *fakeProjectFetcher) getProperties(_ context.Context, _ uuid.UUID) ([]dtrack.ProjectProperty, error) {
	return f.properties, f.propsErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestResolver(fetcher projectFetcher, defaultRepo string) *repoResolver {
	return &repoResolver{dt: fetcher, defaultRepo: defaultRepo}
}

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
		wantRetry   bool  // error must be a *retryableError
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
			name: "returns errNoRepo when nothing resolves and no default set",
			fetcher: &fakeProjectFetcher{
				project: dtrack.Project{Name: "my-service"},
			},
			defaultRepo: "",
			wantErr:     errNoRepo,
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
			var retryErr *retryableError
			switch {
			case tc.wantRetry:
				if !errors.As(err, &retryErr) {
					t.Fatalf("Resolve() error = %v, want retryable error", err)
				}
			case tc.wantErr != nil:
				if errors.As(err, &retryErr) {
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
