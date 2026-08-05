package redact

import (
	"strings"
	"testing"
)

func TestStringScrubsCredentialPatterns(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		mustNot  string
		mustHave string
	}{
		{
			name:     "api token",
			in:       "auth failed for ctfd_9f8e7d6c5b4a39281706abcdef123456",
			mustNot:  "9f8e7d6c",
			mustHave: Placeholder,
		},
		{
			name:     "authorization header",
			in:       `Authorization: Token ctfd_abcdefabcdefabcdefabcdef`,
			mustNot:  "abcdefabcdef",
			mustHave: Placeholder,
		},
		{
			name:     "bearer header",
			in:       `authorization = Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig`,
			mustNot:  "eyJhbGciOiJIUzI1NiJ9",
			mustHave: Placeholder,
		},
		{
			name:     "signed download token in a query string",
			in:       "GET /files/abc/chal.zip?token=eyJ1c2VyX2lkIjo5fQ.signature",
			mustNot:  "signature",
			mustHave: Placeholder,
		},
		{
			name:     "session cookie",
			in:       "Cookie: session=eyJpZCI6OX0.Zm9vYmFy; other=keep",
			mustNot:  "Zm9vYmFy",
			mustHave: Placeholder,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if strings.Contains(got, tc.mustNot) {
				t.Errorf("String(%q) = %q, which still contains %q", tc.in, got, tc.mustNot)
			}
			if !strings.Contains(got, tc.mustHave) {
				t.Errorf("String(%q) = %q, expected it to contain %q", tc.in, got, tc.mustHave)
			}
		})
	}
}

func TestRedactorScrubsRegisteredLiterals(t *testing.T) {
	// A token from a forked or proxied CTFd may not match the expected shape,
	// so the configured value is registered explicitly.
	secret := "unusual-token-format-9182736455"
	r := New(secret)

	got := r.String("request failed with credential " + secret + " attached")
	if strings.Contains(got, secret) {
		t.Errorf("the registered secret survived redaction: %q", got)
	}
	if !strings.Contains(got, Placeholder) {
		t.Errorf("expected a placeholder, got %q", got)
	}
}

func TestRedactorIgnoresShortSecrets(t *testing.T) {
	// Redacting a short string would corrupt unrelated output.
	r := New("abc", "")
	const s = "the abc of it"
	if got := r.String(s); got != s {
		t.Errorf("a short secret should not be scrubbed: got %q, want %q", got, s)
	}
}

func TestRedactorIsIdempotent(t *testing.T) {
	r := New("supersecrettoken1234")
	once := r.String("token supersecrettoken1234 here")
	twice := r.String(once)
	if once != twice {
		t.Errorf("redaction should be stable: %q then %q", once, twice)
	}
}

func TestPreservesNonSecretText(t *testing.T) {
	r := New("supersecrettoken1234")
	const s = "challenge 12 in category crypto is worth 100 points"
	if got := r.String(s); got != s {
		t.Errorf("ordinary text was altered: got %q, want %q", got, s)
	}
}

func TestFingerprintIsStableAndNotReversible(t *testing.T) {
	const secret = "ctfd_abcdefabcdefabcdefabcdef"
	a, b := Fingerprint(secret), Fingerprint(secret)
	if a != b {
		t.Errorf("fingerprints should be stable: %q vs %q", a, b)
	}
	if strings.Contains(a, "abcdef") {
		t.Errorf("the fingerprint leaked the secret: %q", a)
	}
	if Fingerprint(secret) == Fingerprint(secret+"x") {
		t.Error("different secrets should fingerprint differently")
	}
	if Fingerprint("") != "none" {
		t.Errorf("an empty secret should fingerprint as %q", "none")
	}
}

func TestNilRedactorStillAppliesPatterns(t *testing.T) {
	// A zero-value Redactor is easy to construct by accident; it must not
	// silently disable redaction.
	var r *Redactor
	got := r.String("ctfd_abcdefabcdefabcdefabcdef")
	if strings.Contains(got, "abcdefabcdef") {
		t.Errorf("a nil Redactor must still apply the pattern rules, got %q", got)
	}
}

func TestErrorHandlesNil(t *testing.T) {
	r := New()
	if got := r.Error(nil); got != "" {
		t.Errorf("Error(nil) = %q, want an empty string", got)
	}
}
