package ctfd

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Kind classifies a CTFd failure so callers (and the MCP tool layer) can react
// without string-matching messages.
type Kind string

const (
	// KindTransport covers DNS, connection, and TLS failures: the request
	// never reached CTFd, or the response never came back.
	KindTransport Kind = "transport"
	// KindTimeout covers context deadline expiry and slow-response timeouts.
	KindTimeout Kind = "timeout"
	// KindAuth is 401: the token or session is missing, invalid, or expired.
	KindAuth Kind = "auth"
	// KindForbidden is 403: authenticated but not permitted. In CTFd this is
	// also what a hidden scoreboard, an unstarted CTF, and an admin-only
	// endpoint look like to a player.
	KindForbidden Kind = "forbidden"
	// KindNotFound is 404.
	KindNotFound Kind = "not_found"
	// KindValidation is 400/422: the request body or query was rejected.
	KindValidation Kind = "validation"
	// KindRateLimited is 429, or an in-band "ratelimited" submission status.
	KindRateLimited Kind = "rate_limited"
	// KindServer is 5xx.
	KindServer Kind = "server"
	// KindDecode means the response was not the JSON envelope we expected,
	// which usually indicates a login redirect, a proxy error page, or a URL
	// pointing at something that is not CTFd.
	KindDecode Kind = "decode"
	// KindUnexpected is any other non-2xx status.
	KindUnexpected Kind = "unexpected"
)

// Error is a structured CTFd API failure.
type Error struct {
	Kind Kind
	// StatusCode is the HTTP status, or 0 for transport-level failures.
	StatusCode int
	// Method and Path identify the request. Path never contains credentials.
	Method string
	Path   string
	// Message is CTFd's own human-readable message, when it supplied one.
	Message string
	// Fields holds marshmallow field-level validation errors, keyed by field
	// name. CTFd returns these under the "errors" key on 400 responses.
	Fields map[string][]string
	// RetryAfter is the server-advertised wait before retrying, when present.
	RetryAfter time.Duration
	// Body is a truncated copy of the raw response body, for diagnostics.
	Body string
	// Err is the wrapped cause, if any.
	Err error
	// NoRetry forces Retryable to report false even for a Kind that is
	// normally worth another attempt. It marks failures we have positively
	// determined will not resolve themselves, such as a TLS verification
	// error or an unresolvable hostname.
	NoRetry bool
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("ctfd: ")
	if e.Method != "" && e.Path != "" {
		fmt.Fprintf(&b, "%s %s: ", e.Method, e.Path)
	}
	if e.StatusCode > 0 {
		fmt.Fprintf(&b, "HTTP %d %s", e.StatusCode, http.StatusText(e.StatusCode))
	} else {
		b.WriteString(string(e.Kind))
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	if len(e.Fields) > 0 {
		fmt.Fprintf(&b, ": %s", formatFields(e.Fields))
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Retryable reports whether reissuing an identical request could plausibly
// succeed. It deliberately says nothing about whether the request is safe to
// repeat; see idempotency handling in the client.
func (e *Error) Retryable() bool {
	if e.NoRetry {
		return false
	}
	switch e.Kind {
	case KindTransport, KindTimeout, KindRateLimited, KindServer:
		return true
	case KindUnexpected:
		// 408 Request Timeout and 425 Too Early are worth another attempt.
		return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooEarly
	default:
		return false
	}
}

// Hint returns operator-facing guidance for the failure, or "" when the error
// speaks for itself. These strings are surfaced to the model so it can correct
// course instead of retrying blindly.
func (e *Error) Hint() string {
	switch e.Kind {
	case KindAuth:
		return "The CTFd credential was rejected. Verify CTFD_TOKEN is a current token from Settings > Access Tokens and has not been revoked or expired."
	case KindForbidden:
		return "CTFd refused this request. Common causes: the CTF has not started or has ended, the scoreboard is hidden, challenge visibility is restricted, or the endpoint requires an admin account."
	case KindNotFound:
		return "No such resource. It may be hidden from players, not yet released, or the ID may be wrong."
	case KindValidation:
		return "CTFd rejected the request contents. Check the rejected fields above; the values were malformed, out of range, or not permitted in the event's current state."
	case KindRateLimited:
		return "CTFd is rate limiting this client. Wait before retrying; lower CTFD_RATE_LIMIT if this recurs."
	case KindDecode:
		return "The response was not a CTFd API JSON envelope. Check that CTFD_URL points at the CTFd root (not a login page or a reverse-proxy error page) and that credentials are valid."
	case KindServer:
		return "CTFd returned a server error. This is usually transient."
	case KindTransport:
		return "Could not reach CTFd. Check the URL, network access, and (for self-signed certificates) whether CTFD_INSECURE_TLS is needed."
	case KindTimeout:
		return "The request exceeded its timeout. Raise CTFD_TIMEOUT if the instance is slow."
	default:
		return ""
	}
}

func formatFields(f map[string][]string) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(f[k], "; "))
	}
	return strings.Join(parts, ", ")
}

// AsError extracts a *Error from an error chain.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// KindOf reports the Kind of an error, or "" if it is not a CTFd error.
func KindOf(err error) Kind {
	if e, ok := AsError(err); ok {
		return e.Kind
	}
	return ""
}

// IsAuth reports whether err was an authentication failure.
func IsAuth(err error) bool { return KindOf(err) == KindAuth }

// IsNotFound reports whether err was a 404.
func IsNotFound(err error) bool { return KindOf(err) == KindNotFound }

// IsForbidden reports whether err was a 403.
func IsForbidden(err error) bool { return KindOf(err) == KindForbidden }

// IsRateLimited reports whether err was a rate-limit rejection.
func IsRateLimited(err error) bool { return KindOf(err) == KindRateLimited }

// IsAlreadyUnlocked reports whether err is CTFd rejecting an unlock because
// the target is already unlocked.
//
// CTFd returns this as a 400 with a "target" field error rather than as a
// distinguishable status, so the message has to be matched. Callers use it to
// treat a redundant unlock as success instead of failure.
func IsAlreadyUnlocked(err error) bool {
	e, ok := AsError(err)
	if !ok || e.Kind != KindValidation {
		return false
	}
	for _, msg := range e.Fields["target"] {
		if strings.Contains(strings.ToLower(msg), "already unlocked") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(e.Message), "already unlocked")
}

// kindForStatus maps an HTTP status to a Kind.
func kindForStatus(code int) Kind {
	switch {
	case code == http.StatusUnauthorized:
		return KindAuth
	case code == http.StatusForbidden:
		return KindForbidden
	case code == http.StatusNotFound:
		return KindNotFound
	case code == http.StatusBadRequest, code == http.StatusUnprocessableEntity:
		return KindValidation
	case code == http.StatusTooManyRequests:
		return KindRateLimited
	case code >= 500:
		return KindServer
	case code >= 400:
		return KindUnexpected
	default:
		return KindUnexpected
	}
}
