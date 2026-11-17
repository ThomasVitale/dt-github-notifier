package github

import (
	"fmt"
	"path"
	"strings"
)

// Allowlist restricts the repositories issues may be created in.
//
// The repository of a notification is derived from Dependency-Track project
// data that BOM uploads can set, so without an allowlist anyone able to upload
// a BOM could direct issues to any repository the token can write to.
type Allowlist struct {
	patterns []string
}

// NewAllowlist returns an Allowlist of "owner/repo" patterns, where "*"
// matches any owner or repository name (e.g. "myorg/*" or "*/*"). Matching
// is case-insensitive, like GitHub names.
func NewAllowlist(patterns []string) (*Allowlist, error) {
	a := &Allowlist{}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		owner, repo, ok := strings.Cut(p, "/")
		if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
			return nil, fmt.Errorf("invalid repository pattern %q: want \"owner/repo\", \"owner/*\" or \"*/*\"", p)
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid repository pattern %q: %w", p, err)
		}
		a.patterns = append(a.patterns, p)
	}
	if len(a.patterns) == 0 {
		return nil, fmt.Errorf("no repository patterns")
	}
	return a, nil
}

// Allows reports whether issues may be created in repo.
func (a *Allowlist) Allows(repo string) bool {
	repo = strings.ToLower(repo)
	for _, p := range a.patterns {
		// path.Match's "*" does not match "/", so it stays within the owner or
		// repository name.
		if ok, _ := path.Match(p, repo); ok {
			return true
		}
	}
	return false
}
