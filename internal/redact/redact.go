// Package redact removes credentials from strings before they reach logs,
// error messages, or model-visible tool output.
//
// The MCP transport hands tool results straight to a language model, and this
// server's stderr is typically captured by the MCP client. A CTFd API token
// leaking into either is a real credential disclosure, so redaction is applied
// centrally rather than at each call site.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Placeholder replaces any redacted value.
const Placeholder = "[REDACTED]"

// tokenPattern matches CTFd API tokens, which are minted with a "ctfd_"
// prefix followed by a long hex/base-something body.
var tokenPattern = regexp.MustCompile(`ctfd_[A-Za-z0-9_\-]{16,}`)

// bearerPattern matches Authorization header values in either the "Token" or
// "Bearer" form, so a dumped request never exposes the credential.
var bearerPattern = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(token|bearer)\s+\S+`)

// cookiePattern matches session cookie assignments.
var cookiePattern = regexp.MustCompile(`(?i)\b(session|csrf_?token|csrf_?nonce)\s*=\s*[^;,\s"']+`)

// queryTokenPattern matches credentials smuggled into a query string, which is
// how CTFd serves authenticated file downloads (/files/<path>?token=...).
var queryTokenPattern = regexp.MustCompile(`(?i)([?&](?:token|api_?key|nonce|session)=)[^&\s]+`)

// Redactor removes a known set of literal secrets in addition to the
// pattern-based rules. Registering the actual configured credential catches
// tokens that do not match the expected shape, such as those issued by a
// forked or proxied CTFd.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// New returns a Redactor that additionally scrubs the given literal secrets.
// Empty and very short values are ignored: redacting a 3-character string
// would corrupt unrelated output.
func New(secrets ...string) *Redactor {
	r := &Redactor{}
	for _, s := range secrets {
		r.Add(s)
	}
	return r
}

// Add registers another literal secret to scrub.
func (r *Redactor) Add(secret string) {
	secret = strings.TrimSpace(secret)
	if len(secret) < 8 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.secrets {
		if existing == secret {
			return
		}
	}
	r.secrets = append(r.secrets, secret)
}

// String scrubs s of every registered secret and every known credential
// pattern.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	if r != nil {
		r.mu.RLock()
		secrets := r.secrets
		r.mu.RUnlock()
		for _, secret := range secrets {
			s = strings.ReplaceAll(s, secret, Placeholder)
		}
	}
	return String(s)
}

// Error scrubs an error's message, preserving the ability to compare kinds via
// the returned wrapper only as a string. Callers that need errors.Is/As should
// redact at the point of formatting instead.
func (r *Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(err.Error())
}

// String applies the pattern-based rules without any registered literals. It
// is safe to call on arbitrary untrusted text.
func String(s string) string {
	if s == "" {
		return s
	}
	s = bearerPattern.ReplaceAllString(s, "${1}${2} "+Placeholder)
	s = queryTokenPattern.ReplaceAllString(s, "${1}"+Placeholder)
	s = cookiePattern.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.Index(m, "=")
		if i < 0 {
			return Placeholder
		}
		return m[:i+1] + Placeholder
	})
	s = tokenPattern.ReplaceAllString(s, Placeholder)
	return s
}

// Fingerprint returns a short, stable, non-reversible identifier for a
// credential. It lets logs distinguish "the token changed" from "the same
// token keeps failing" without ever recording the token.
func Fingerprint(secret string) string {
	if secret == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// LogValue lets a Redactor-scrubbed string be attached to a slog record
// lazily, so the cost is only paid when the record is actually emitted.
type LogValue struct {
	R *Redactor
	S string
}

func (v LogValue) String() string { return v.R.String(v.S) }

var _ fmt.Stringer = LogValue{}
