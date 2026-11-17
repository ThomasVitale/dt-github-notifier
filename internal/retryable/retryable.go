// Package retryable marks errors caused by transient failures, so that callers
// can ask the client to try again later.
package retryable

import (
	"errors"
	"time"
)

// Error wraps a transient failure.
type Error struct {
	Err   error
	After time.Duration // how long to wait before retrying; zero when unknown
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Wrap marks err as retryable after the given delay (zero when unknown).
func Wrap(err error, after time.Duration) error {
	return &Error{Err: err, After: after}
}

// As reports whether err is retryable and, if so, after how long.
func As(err error) (time.Duration, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.After, true
	}
	return 0, false
}
