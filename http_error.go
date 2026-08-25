package globalping

import (
	"fmt"
	"net/http"
)

// HTTPError represents a non-successful HTTP response from the Globalping API.
type HTTPError struct {
	StatusCode int
	Header     http.Header
	cause      error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s", e.StatusCode, http.StatusText(e.StatusCode))
}

func (e *HTTPError) Unwrap() error {
	return e.cause
}

func newHTTPError(statusCode int, header http.Header) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Header:     header,
	}
}

func newHTTPErrorWithCause(statusCode int, header http.Header, cause error) *HTTPError {
	err := newHTTPError(statusCode, header)
	err.cause = cause

	return err
}
