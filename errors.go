package main

import (
	"errors"
	"time"
)

// retryableError marks a transient failure. The webhook handler answers it with
// 503, which Dependency-Track retries (honouring Retry-After when set).
type retryableError struct {
	err        error
	retryAfter time.Duration // zero when unknown
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

func retryable(err error, retryAfter time.Duration) error {
	return &retryableError{err: err, retryAfter: retryAfter}
}

// errNoRepo is returned when no GitHub repo could be resolved for a project
// and no fallback repo is configured.
var errNoRepo = errors.New("no GitHub repo could be resolved")
