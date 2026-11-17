package webhook

import (
	"sync"
	"time"

	"github.com/thomasvitale/dt-github-notifier/internal/issue"
)

// recentIssues remembers the issues handled recently, by repo and issue key.
//
// GitHub's search index lags a few seconds to minutes behind newly created
// issues, so a notification retried by Dependency-Track shortly after its
// issue was created would not find it by search and create a duplicate.
type recentIssues struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu      sync.Mutex
	entries map[string]recentIssue
}

type recentIssue struct {
	ref     issue.Ref
	expires time.Time
}

func newRecentIssues(ttl time.Duration, maxEntries int) *recentIssues {
	return &recentIssues{ttl: ttl, max: maxEntries, now: time.Now, entries: make(map[string]recentIssue)}
}

// get returns the issue recently handled under key, if any.
func (r *recentIssues) get(key string) (issue.Ref, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok || r.now().After(e.expires) {
		return issue.Ref{}, false
	}
	return e.ref, true
}

// remove forgets the issue handled under key, e.g. once it is closed.
func (r *recentIssues) remove(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
}

// add remembers the issue handled under key. When full, it evicts expired
// entries first and then arbitrary ones, bounding memory use.
func (r *recentIssues) add(key string, ref issue.Ref) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if len(r.entries) >= r.max {
		for k, e := range r.entries {
			if now.After(e.expires) {
				delete(r.entries, k)
			}
		}
	}
	for k := range r.entries {
		if len(r.entries) < r.max {
			break
		}
		delete(r.entries, k)
	}
	r.entries[key] = recentIssue{ref: ref, expires: now.Add(r.ttl)}
}
