package ctfd

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Backoff computes retry delays using exponential growth with full jitter.
//
// Full jitter (delay = random(0, base*2^attempt)) is used rather than
// equal jitter or none, because every MCP client instance of this server
// points at the same CTFd instance and would otherwise retry in lockstep.
type Backoff struct {
	// Base is the delay for attempt 0 before jitter.
	Base time.Duration
	// Max caps the pre-jitter delay.
	Max time.Duration
	// Rand returns a float in [0,1). Injectable so tests are deterministic.
	Rand func() float64
}

// DefaultBackoff is tuned for a CTFd instance under competition load: quick
// first retry, but backing off fast enough not to add to a thundering herd.
func DefaultBackoff() Backoff {
	return Backoff{Base: 250 * time.Millisecond, Max: 20 * time.Second, Rand: rand.Float64}
}

// Delay returns the wait before the given zero-indexed retry attempt.
func (b Backoff) Delay(attempt int) time.Duration {
	base, max := b.Base, b.Max
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	if max <= 0 {
		max = 20 * time.Second
	}
	if attempt < 0 {
		attempt = 0
	}
	// Cap the exponent before shifting so a large attempt count cannot
	// overflow the multiplication into a negative duration.
	exp := math.Min(float64(attempt), 20)
	d := time.Duration(float64(base) * math.Pow(2, exp))
	if d > max || d <= 0 {
		d = max
	}
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	return time.Duration(r() * float64(d))
}

// maxRetryAfter bounds how long a server-advertised Retry-After will be
// honored. A hostile or misconfigured proxy can send an enormous value; past
// this point we fall back to our own backoff rather than stalling a tool call.
const maxRetryAfter = 60 * time.Second

// parseRetryAfter interprets a Retry-After header in both permitted forms:
// delta-seconds ("120") and HTTP-date ("Wed, 21 Oct 2015 07:28:00 GMT").
// now is injectable for testing. It returns ok=false when the header is
// absent or unparseable.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.ParseFloat(h, 64); err == nil {
		if secs < 0 || math.IsNaN(secs) || math.IsInf(secs, 0) {
			return 0, false
		}
		return time.Duration(secs * float64(time.Second)), true
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d < 0 {
			// A past date means "retry now".
			return 0, true
		}
		return d, true
	}
	return 0, false
}

// retryDelay picks the wait before the next attempt, preferring the server's
// Retry-After when it is present and sane.
func retryDelay(b Backoff, attempt int, retryAfter time.Duration, hasRetryAfter bool) time.Duration {
	if hasRetryAfter && retryAfter >= 0 && retryAfter <= maxRetryAfter {
		// Add a small jitter on top so concurrent clients handed the same
		// Retry-After do not all resume at the identical instant.
		r := b.Rand
		if r == nil {
			r = rand.Float64
		}
		return retryAfter + time.Duration(r()*float64(250*time.Millisecond))
	}
	return b.Delay(attempt)
}

// isRetryableNetErr reports whether a transport-level error is worth another
// attempt. Errors caused by a cancelled or expired caller context are never
// retryable: the caller has already given up.
func isRetryableNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// A truncated response is retryable: the connection died mid-body, often
	// because a keep-alive connection was reaped between requests.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// Connection reset / refused / broken pipe: the peer went away, commonly a
	// rolling restart or an overloaded gunicorn worker.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// DNS failures are retryable only when the resolver reported a temporary
	// condition; NXDOMAIN will not fix itself.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// A failure to establish the connection at all is retryable; a
		// failure during TLS verification is not, since the certificate will
		// not become valid on retry.
		return opErr.Op == "dial" || opErr.Op == "read"
	}

	// http.Client wraps transport errors in *url.Error; the checks above
	// already unwrap through it via errors.As/Is. Anything else is treated as
	// permanent so we fail fast and loudly rather than hammering the server.
	//
	// One exception: net/http reports this specific string when it declines to
	// retry a request whose body it could not rewind.
	return strings.Contains(err.Error(), "http: server closed idle connection")
}

// isRetryableStatus reports whether an HTTP status warrants another attempt.
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusInsufficientStorage:
		return true
	default:
		return false
	}
}

// sleepCtx waits for d, returning early with the context error if the context
// is done first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
