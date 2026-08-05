package ctfd

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func TestBackoffGrowsAndStaysWithinCap(t *testing.T) {
	// Rand fixed at its maximum so the pre-jitter ceiling is observable.
	b := Backoff{Base: 100 * time.Millisecond, Max: 2 * time.Second, Rand: func() float64 { return 0.999999 }}

	var prev time.Duration
	for attempt := 0; attempt < 8; attempt++ {
		d := b.Delay(attempt)
		if d > b.Max {
			t.Errorf("attempt %d: delay %s exceeds cap %s", attempt, d, b.Max)
		}
		if d < 0 {
			t.Errorf("attempt %d: negative delay %s", attempt, d)
		}
		if attempt > 0 && attempt < 5 && d < prev {
			t.Errorf("attempt %d: delay %s should not shrink from %s before the cap", attempt, d, prev)
		}
		prev = d
	}
}

func TestBackoffDoesNotOverflowAtLargeAttemptCounts(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 30 * time.Second, Rand: func() float64 { return 1 }}
	for _, attempt := range []int{-1, 0, 62, 63, 64, 1 << 20} {
		d := b.Delay(attempt)
		if d < 0 || d > b.Max {
			t.Errorf("attempt %d produced %s, want 0..%s", attempt, d, b.Max)
		}
	}
}

func TestBackoffJitterSpreadsRetries(t *testing.T) {
	// Full jitter must actually vary; identical delays would resynchronize
	// every client that backed off at the same moment.
	seq := []float64{0.1, 0.9, 0.5}
	i := 0
	b := Backoff{Base: time.Second, Max: time.Minute, Rand: func() float64 {
		v := seq[i%len(seq)]
		i++
		return v
	}}
	a, c := b.Delay(3), b.Delay(3)
	if a == c {
		t.Errorf("expected jittered delays to differ, both were %s", a)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		header string
		want   time.Duration
		wantOK bool
	}{
		{"empty", "", 0, false},
		{"delta seconds", "120", 120 * time.Second, true},
		{"zero", "0", 0, true},
		{"fractional", "1.5", 1500 * time.Millisecond, true},
		{"negative is rejected", "-5", 0, false},
		{"http date in the future", "Sat, 01 Aug 2026 12:00:30 GMT", 30 * time.Second, true},
		{"http date in the past clamps to zero", "Sat, 01 Aug 2026 11:59:00 GMT", 0, true},
		{"garbage", "soon please", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.header, now)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("duration = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRetryDelayIgnoresAbsurdRetryAfter(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 5 * time.Second, Rand: func() float64 { return 0.5 }}

	// A hostile or misconfigured proxy can advertise an enormous wait; falling
	// back to our own schedule keeps a tool call from stalling indefinitely.
	got := retryDelay(b, 0, 24*time.Hour, true)
	if got > b.Max {
		t.Errorf("delay = %s, want it capped at %s when Retry-After is absurd", got, b.Max)
	}

	// A reasonable value is honored, plus a small jitter.
	got = retryDelay(b, 0, 2*time.Second, true)
	if got < 2*time.Second || got > 2*time.Second+250*time.Millisecond {
		t.Errorf("delay = %s, want just over 2s", got)
	}
}

func TestIsRetryableNetErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context cancelled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"connection refused", syscall.ECONNREFUSED, true},
		{"permanent DNS failure", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"temporary DNS failure", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"dial failure", &net.OpError{Op: "dial", Err: errors.New("boom")}, true},
		{"unknown error", errors.New("certificate signed by unknown authority"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableNetErr(tc.err); got != tc.want {
				t.Errorf("isRetryableNetErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{429, 408, 425, 500, 502, 503, 504, 507}
	for _, code := range retryable {
		if !isRetryableStatus(code) {
			t.Errorf("status %d should be retryable", code)
		}
	}
	permanent := []int{200, 201, 400, 401, 403, 404, 409, 422}
	for _, code := range permanent {
		if isRetryableStatus(code) {
			t.Errorf("status %d must not be retried", code)
		}
	}
}

func TestSleepCtxReturnsEarlyOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Fatal("expected a context error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepCtx blocked for %s after cancellation", elapsed)
	}
}

func TestErrorRetryableRespectsNoRetry(t *testing.T) {
	e := &Error{Kind: KindServer}
	if !e.Retryable() {
		t.Error("a 5xx should normally be retryable")
	}
	e.NoRetry = true
	if e.Retryable() {
		t.Error("NoRetry must override the Kind-based decision")
	}
}

func TestKindForStatus(t *testing.T) {
	cases := map[int]Kind{
		http.StatusUnauthorized:        KindAuth,
		http.StatusForbidden:           KindForbidden,
		http.StatusNotFound:            KindNotFound,
		http.StatusBadRequest:          KindValidation,
		http.StatusUnprocessableEntity: KindValidation,
		http.StatusTooManyRequests:     KindRateLimited,
		http.StatusInternalServerError: KindServer,
		http.StatusBadGateway:          KindServer,
		http.StatusConflict:            KindUnexpected,
	}
	for status, want := range cases {
		if got := kindForStatus(status); got != want {
			t.Errorf("kindForStatus(%d) = %q, want %q", status, got, want)
		}
	}
}
