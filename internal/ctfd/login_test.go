package ctfd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCTFdAuth emulates CTFd's real session and CSRF behavior closely enough to
// prove the login and cookie-auth write paths work:
//
//   - GET /login sets a session cookie and embeds the nonce in the page.
//   - POST /login checks the nonce from the FORM body (non-JSON content type),
//     verifies credentials, then rotates the session and nonce.
//   - Any write with a session checks the nonce from the CSRF-Token HEADER
//     (JSON content type), rejecting a mismatch with a bare 403.
//   - Requests with an Authorization header bypass CSRF entirely.
type fakeCTFdAuth struct {
	*httptest.Server

	mu       sync.Mutex
	nonce    string
	session  string
	authed   bool
	attempts int
	// csrfRejections counts writes rejected for a bad nonce.
	csrfRejections int
	// nonceHeaders records the CSRF-Token header seen on each write.
	nonceHeaders []string
}

func newFakeCTFdAuth(t *testing.T, username, password string) *fakeCTFdAuth {
	t.Helper()
	f := &fakeCTFdAuth{nonce: "aaaa1111bbbb2222cccc3333dddd4444", session: "sess-initial"}

	// checkCSRF mirrors CTFd's csrf() before_request hook.
	checkCSRF := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "" {
			return true // token auth bypasses CSRF
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			return true
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.nonceHeaders = append(f.nonceHeaders, r.Header.Get("CSRF-Token"))
		if r.Header.Get("CSRF-Token") != f.nonce {
			f.csrfRejections++
			// CTFd aborts with a bare 403 and no body.
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}

	loggedIn := func(r *http.Request) bool {
		if r.Header.Get("Authorization") != "" {
			return true
		}
		c, err := r.Cookie("session")
		if err != nil {
			return false
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.authed && c.Value == f.session
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		sess, nonce := f.session, f.nonce
		f.mu.Unlock()

		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sess, Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><script>var init = {'csrfNonce': "` + nonce + `"};</script></html>`))
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Non-JSON content type: CTFd reads the nonce from the form body.
		if r.PostForm.Get("nonce") != nonce {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.PostForm.Get("name") != username || r.PostForm.Get("password") != password {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Your username or password is incorrect</body></html>`))
			return
		}

		// Success: session.regenerate() rotates both the session and nonce.
		f.mu.Lock()
		f.session = "sess-authenticated"
		f.nonce = "ffff9999eeee8888dddd7777cccc6666"
		f.authed = true
		newSess := f.session
		f.mu.Unlock()

		http.SetCookie(w, &http.Cookie{Name: "session", Value: newSess, Path: "/"})
		w.Header().Set("Location", "/challenges")
		w.WriteHeader(http.StatusFound)
	})

	mux.HandleFunc("/challenges", func(w http.ResponseWriter, r *http.Request) {
		if !loggedIn(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		nonce := f.nonce
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><script>var init = {'csrfNonce': "` + nonce + `"};</script></html>`))
	})

	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		if !loggedIn(r) {
			writeJSON(w, 403, `{"success":false,"message":"forbidden"}`)
			return
		}
		writeJSON(w, 200, `{"success":true,"data":{"id":5,"name":"`+username+`","team_id":null}}`)
	})

	mux.HandleFunc("/api/v1/challenges/attempt", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) {
			return
		}
		if !loggedIn(r) {
			writeJSON(w, 403, `{"success":true,"data":{"status":"authentication_required"}}`)
			return
		}
		f.mu.Lock()
		f.attempts++
		f.mu.Unlock()
		writeJSON(w, 200, `{"success":true,"data":{"status":"correct","message":"Correct!"}}`)
	})

	mux.HandleFunc("/api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		if !checkCSRF(w, r) {
			return
		}
		if !loggedIn(r) {
			writeJSON(w, 403, `{"success":false}`)
			return
		}
		if r.Method == http.MethodPost {
			writeJSON(w, 200, `{"success":true,"data":{"id":3,"type":"user","user_id":5,"created":"2026-08-01T00:00:00","expiration":"2026-08-31T00:00:00","description":"test","value":"ctfd_mintedtoken000000000000000000"}}`)
			return
		}
		writeJSON(w, 200, `{"success":true,"data":[{"id":1,"type":"user","created":"2026-07-01T00:00:00","expiration":"2026-07-31T00:00:00","description":"old"}]}`)
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCTFdAuth) counts() (attempts, rejections int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts, f.csrfRejections
}

// newLoginClient builds a password-authenticating client against f.
func newLoginClient(t *testing.T, f *fakeCTFdAuth, username, password string) *Client {
	t.Helper()
	base, err := url.Parse(f.URL + "/")
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	// A real cookie jar, because the whole point is that the session survives
	// between requests.
	c, err := NewClient(Options{
		BaseURL:   base,
		Username:  username,
		Password:  password,
		Timeout:   5 * time.Second,
		RateLimit: 1000, RateBurst: 1000,
		SubmitRate: 1000, SubmitBurst: 1000,
		PerPage: 50, MaxPages: 5,
		Backoff: &Backoff{Base: 0, Max: 0, Rand: func() float64 { return 0 }},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestLoginEstablishesSession(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")

	me, err := c.Login(context.Background(), "player1", "hunter2")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if me.Name != "player1" {
		t.Errorf("logged in as %q, want player1", me.Name)
	}
	if !c.LoggedIn() {
		t.Error("LoggedIn() should report true after a successful login")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "wrong")

	_, err := c.Login(context.Background(), "player1", "wrong")
	if err == nil {
		t.Fatal("expected a login failure")
	}
	if !IsAuth(err) {
		t.Errorf("expected an auth-kind error, got %v", err)
	}
	if !strings.Contains(err.Error(), "username or password") {
		t.Errorf("error should name the cause: %v", err)
	}
}

// TestSubmitFlagUnderSessionAuth is the test that proves a password-only user
// can actually play. It exercises the whole chain: login, nonce rotation on
// session regeneration, and a JSON write carrying the CSRF-Token header.
func TestSubmitFlagUnderSessionAuth(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")
	ctx := context.Background()

	if _, err := c.Login(ctx, "player1", "hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	res, err := c.Attempt(ctx, 1, "flag{session_auth_works}")
	if err != nil {
		t.Fatalf("Attempt under session auth: %v", err)
	}
	if res.Status != AttemptCorrect {
		t.Errorf("Status = %q, want correct", res.Status)
	}

	attempts, rejections := f.counts()
	if attempts != 1 {
		t.Errorf("server recorded %d attempts, want 1", attempts)
	}
	if rejections != 0 {
		t.Errorf("the submission was CSRF-rejected %d times; the nonce must be refreshed after login rotates it", rejections)
	}

	// The write must have carried the post-login nonce, not the pre-login one.
	f.mu.Lock()
	seen := append([]string(nil), f.nonceHeaders...)
	f.mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no CSRF-Token header was sent on the write")
	}
	if seen[len(seen)-1] != "ffff9999eeee8888dddd7777cccc6666" {
		t.Errorf("write carried nonce %q, want the rotated post-login value", seen[len(seen)-1])
	}
}

// TestStaleNonceIsRecovered covers the long-running case: CTFd rotates the
// session nonce, the cached one goes stale, and the next write is rejected
// with a bare 403. Because CTFd checks the nonce in a before_request hook, no
// attempt was recorded, so refreshing and retrying once is safe.
func TestStaleNonceIsRecovered(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")
	ctx := context.Background()

	if _, err := c.Login(ctx, "player1", "hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Prime the cached nonce with a successful write.
	if _, err := c.Attempt(ctx, 1, "flag{first}"); err != nil {
		t.Fatalf("first Attempt: %v", err)
	}

	// The server rotates its nonce out from under the client.
	f.mu.Lock()
	f.nonce = "1234abcd5678efab9012cdef3456abcd"
	f.mu.Unlock()

	res, err := c.Attempt(ctx, 1, "flag{second}")
	if err != nil {
		t.Fatalf("Attempt after a nonce rotation should recover, got: %v", err)
	}
	if res.Status != AttemptCorrect {
		t.Errorf("Status = %q, want correct", res.Status)
	}

	attempts, rejections := f.counts()
	if rejections != 1 {
		t.Errorf("expected exactly 1 CSRF rejection before recovery, got %d", rejections)
	}
	// Two successful submissions total. The rejected one never reached the
	// handler, so it must not have counted.
	if attempts != 2 {
		t.Errorf("server recorded %d attempts, want 2; a CSRF-rejected write must not consume one", attempts)
	}
}

func TestTokenAuthSendsNoCSRFNonce(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	base, _ := url.Parse(f.URL + "/")
	c, err := NewClient(Options{
		BaseURL: base, Token: "ctfd_" + strings.Repeat("a", 64),
		Timeout: 5 * time.Second, RateLimit: 1000, RateBurst: 1000,
		SubmitRate: 1000, SubmitBurst: 1000,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Attempt(context.Background(), 1, "flag{x}"); err != nil {
		t.Fatalf("Attempt with token auth: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.nonceHeaders) != 0 {
		t.Errorf("token auth should bypass CSRF entirely, but a nonce was checked: %v", f.nonceHeaders)
	}
}

func TestEnsureLoginIsIdempotentAndConcurrencySafe(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.EnsureLogin(ctx)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent EnsureLogin %d failed: %v", i, err)
		}
	}
	if !c.LoggedIn() {
		t.Error("client should be logged in")
	}
	// A second call after success must be a no-op.
	if err := c.EnsureLogin(ctx); err != nil {
		t.Errorf("repeat EnsureLogin: %v", err)
	}
}

func TestEnsureLoginIsNoOpForTokenAuth(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	base, _ := url.Parse(f.URL + "/")
	c, err := NewClient(Options{
		BaseURL: base, Token: "ctfd_" + strings.Repeat("a", 64),
		Timeout: 5 * time.Second, RateLimit: 1000, RateBurst: 1000,
		SubmitRate: 1000, SubmitBurst: 1000,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.NeedsLogin() {
		t.Error("a token client must not need a login")
	}
	if err := c.EnsureLogin(context.Background()); err != nil {
		t.Errorf("EnsureLogin should be a no-op for token auth, got %v", err)
	}
}

func TestCreateTokenReturnsValueOnce(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")
	ctx := context.Background()

	if _, err := c.Login(ctx, "player1", "hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	tok, err := c.CreateToken(ctx, "test", "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Value == "" {
		t.Error("a newly created token must carry its plaintext value")
	}
	// The new value must now be scrubbed from logs and errors.
	if got := c.red.String("leaked " + tok.Value); strings.Contains(got, tok.Value) {
		t.Error("a newly minted token should be registered for redaction")
	}
}

func TestCreateTokenRejectsBadExpirationBeforeSending(t *testing.T) {
	f := newFakeCTFdAuth(t, "player1", "hunter2")
	c := newLoginClient(t, f, "player1", "hunter2")
	ctx := context.Background()

	if _, err := c.Login(ctx, "player1", "hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// CTFd parses this with strptime and lets a ValueError escape as a 500,
	// so a malformed date must be caught client-side.
	_, err := c.CreateToken(ctx, "test", "31/08/2026")
	if err == nil {
		t.Fatal("expected a malformed expiration to be rejected")
	}
	if !strings.Contains(err.Error(), "YYYY-MM-DD") {
		t.Errorf("error should state the required format: %v", err)
	}
}

func TestTokenExpiryDetection(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		exp  string
		want bool
	}{
		{"2026-07-01T00:00:00", true},
		{"2026-09-01T00:00:00", false},
		{"2026-08-01T00:00:00Z", true},
		{"", false},
		{"not a date", false},
	}
	for _, tc := range cases {
		if got := (Token{Expiration: tc.exp}).Expired(now); got != tc.want {
			t.Errorf("Token{Expiration:%q}.Expired() = %v, want %v", tc.exp, got, tc.want)
		}
	}
}
