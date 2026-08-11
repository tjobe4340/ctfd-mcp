package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestEndToEndOverStdio builds the real binary and drives it as a subprocess
// over stdio, exactly as an MCP client does. It is the only test that covers
// process startup, flag and environment handling, transport wiring, and
// shutdown together.
func TestEndToEndOverStdio(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in short mode")
	}

	ctfd := newStubCTFd(t)
	bin := buildBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"CTFD_URL="+ctfd.URL,
		"CTFD_TOKEN=ctfd_"+strings.Repeat("a", 64),
		"CTFD_LOG_LEVEL=error",
		// Keep the run hermetic and fast.
		"CTFD_ALLOW_SUBMIT=false",
		"CTFD_CACHE_TTL=0",
	)
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to the server subprocess: %v", err)
	}
	defer sess.Close()

	t.Run("advertises tools", func(t *testing.T) {
		res, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if len(res.Tools) == 0 {
			t.Fatal("the server advertised no tools")
		}
		found := false
		for _, tool := range res.Tools {
			if tool.Name == "ctfd_whoami" {
				found = true
			}
			// A tool whose schema does not round-trip through JSON would fail
			// inside a client rather than here, so check it now.
			if _, err := json.Marshal(tool.InputSchema); err != nil {
				t.Errorf("tool %s has an unmarshalable input schema: %v", tool.Name, err)
			}
		}
		if !found {
			t.Error("ctfd_whoami was not advertised")
		}
	})

	t.Run("calls a tool against a live CTFd", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "ctfd_whoami"})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("ctfd_whoami failed: %s", contentText(res))
		}
		if !strings.Contains(contentText(res), "e2e-player") {
			t.Errorf("output should name the authenticated user:\n%s", contentText(res))
		}
	})

	t.Run("refuses submission while disabled", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "ctfd_submit_flag",
			Arguments: map[string]any{"challenge_id": 1, "flag": "flag{x}"},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !strings.Contains(contentText(res), "disabled") {
			t.Errorf("expected a disabled notice:\n%s", contentText(res))
		}
		if ctfd.attempts() != 0 {
			t.Error("a submission reached CTFd despite being disabled")
		}
	})

	t.Run("authenticates every request", func(t *testing.T) {
		// CTFd ignores the token unless Content-Type is exactly
		// application/json, which would make reads silently anonymous.
		if bad := ctfd.badRequests(); len(bad) > 0 {
			t.Errorf("requests reached CTFd without proper auth headers: %v", bad)
		}
	})
}

// TestPasswordLoginAndSubmitOverStdio is the end-to-end proof that someone
// holding only a username and password -- no API token -- can start this
// server, be logged in automatically, and submit a flag.
//
// It runs the real binary as a subprocess against a CTFd stub that enforces
// the actual session and CSRF rules: the nonce comes from the login page, the
// session and nonce both rotate on successful login, and a JSON write is
// rejected unless it carries the current nonce in the CSRF-Token header.
func TestPasswordLoginAndSubmitOverStdio(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in short mode")
	}

	ctfd := newLoginCTFd(t, "player1", "hunter2")
	bin := buildBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"CTFD_URL="+ctfd.URL,
		"CTFD_USERNAME=player1",
		"CTFD_PASSWORD=hunter2",
		"CTFD_ALLOW_SUBMIT=true",
		"CTFD_LOG_LEVEL=error",
		"CTFD_CACHE_TTL=0",
		// Ensure no stray token in the developer's environment takes over.
		"CTFD_TOKEN=",
		"CTFD_SESSION=",
	)
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-login", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to the server subprocess: %v", err)
	}
	defer sess.Close()

	t.Run("logged in with a password", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "ctfd_whoami"})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("ctfd_whoami failed: %s", contentText(res))
		}
		if !strings.Contains(contentText(res), "player1") {
			t.Errorf("should be authenticated as player1:\n%s", contentText(res))
		}
		if !strings.Contains(contentText(res), "password-login") {
			t.Errorf("should report password-login as the auth method:\n%s", contentText(res))
		}
	})

	t.Run("submits a flag over the session", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "ctfd_submit_flag",
			Arguments: map[string]any{"challenge_id": 1, "flag": "flag{end_to_end}"},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("submission failed: %s", contentText(res))
		}
		if !strings.Contains(contentText(res), "CORRECT") {
			t.Errorf("expected a correct verdict:\n%s", contentText(res))
		}
		if got := ctfd.accepted(); got != 1 {
			t.Errorf("CTFd recorded %d submissions, want 1", got)
		}
		if got := ctfd.csrfRejected(); got != 0 {
			t.Errorf("the submission was CSRF-rejected %d times", got)
		}
	})

	t.Run("mints an API token", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "ctfd_create_token",
			Arguments: map[string]any{"description": "from e2e", "confirm": true},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("token creation failed: %s", contentText(res))
		}
		if !strings.Contains(contentText(res), "ctfd_e2eminted") {
			t.Errorf("the minted token value should be returned once:\n%s", contentText(res))
		}
	})
}

// loginCTFd is a CTFd stub that enforces the real login and CSRF rules.
type loginCTFd struct {
	*httptest.Server
	mu        sync.Mutex
	nonce     string
	session   string
	authed    bool
	submits   int
	csrfFails int
}

func newLoginCTFd(t *testing.T, username, password string) *loginCTFd {
	t.Helper()
	s := &loginCTFd{nonce: "1111aaaa2222bbbb3333cccc4444dddd", session: "pre-login"}

	page := func(nonce string) string {
		return `<html><script>var init = {'csrfNonce': "` + nonce + `"};</script></html>`
	}
	authOK := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		if err != nil {
			return false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.authed && c.Value == s.session
	}
	// csrfOK mirrors CTFd: JSON writes are checked against the CSRF-Token header.
	csrfOK := func(w http.ResponseWriter, r *http.Request) bool {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return true
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Header.Get("CSRF-Token") != s.nonce {
			s.csrfFails++
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		sess, nonce := s.session, s.nonce
		s.mu.Unlock()

		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sess, Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page(nonce)))
			return
		}
		_ = r.ParseForm()
		// Form posts carry the nonce in the body, not a header.
		if r.PostForm.Get("nonce") != nonce {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.PostForm.Get("name") != username || r.PostForm.Get("password") != password {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html>Your username or password is incorrect</html>`))
			return
		}
		s.mu.Lock()
		// CTFd nonces are hex (generate_nonce hexlifies random bytes), which
		// is what the client's extraction pattern expects.
		s.session, s.nonce, s.authed = "post-login", "9999eeee8888ffff7777aaaa6666bbbb", true
		newSess := s.session
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: newSess, Path: "/"})
		w.Header().Set("Location", "/challenges")
		w.WriteHeader(http.StatusFound)
	})

	mux.HandleFunc("/challenges", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		s.mu.Lock()
		nonce := s.nonce
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page(nonce)))
	})

	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			writeJSONBody(w, 403, `{"success":false,"message":"forbidden"}`)
			return
		}
		writeJSONBody(w, 200, `{"success":true,"data":{"id":5,"name":"`+username+`","team_id":null}}`)
	})
	mux.HandleFunc("/api/v1/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, 200, `{"success":true,"data":[{"pos":1,"account_id":5,"account_type":"user","name":"`+username+`","score":100}]}`)
	})
	mux.HandleFunc("/api/v1/challenges/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, 200, `{"success":true,"data":{"id":1,"name":"Test","value":100,"category":"misc","max_attempts":0,"attempts":0,"solved_by_me":false,"description":"d","files":[],"tags":[],"hints":[]}}`)
	})
	mux.HandleFunc("/api/v1/challenges/attempt", func(w http.ResponseWriter, r *http.Request) {
		if !csrfOK(w, r) {
			return
		}
		if !authOK(r) {
			writeJSONBody(w, 403, `{"success":true,"data":{"status":"authentication_required"}}`)
			return
		}
		s.mu.Lock()
		s.submits++
		s.mu.Unlock()
		writeJSONBody(w, 200, `{"success":true,"data":{"status":"correct","message":"Correct!"}}`)
	})
	mux.HandleFunc("/api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		if !csrfOK(w, r) {
			return
		}
		if !authOK(r) {
			writeJSONBody(w, 403, `{"success":false}`)
			return
		}
		writeJSONBody(w, 200, `{"success":true,"data":{"id":9,"type":"user","created":"2026-08-01T00:00:00","expiration":"2026-08-31T00:00:00","description":"from e2e","value":"ctfd_e2eminted00000000000000000000"}}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, 200, `{"success":true,"data":[]}`)
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *loginCTFd) accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submits
}

func (s *loginCTFd) csrfRejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csrfFails
}

func writeJSONBody(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// TestLiteProfileOverStdio confirms CTFD_LITE actually reaches the running
// server, since the flag is only useful if the process wires it through.
func TestLiteProfileOverStdio(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in short mode")
	}

	ctfd := newStubCTFd(t)
	bin := buildBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"CTFD_URL="+ctfd.URL,
		"CTFD_TOKEN=ctfd_"+strings.Repeat("a", 64),
		"CTFD_LITE=true",
		"CTFD_LOG_LEVEL=error",
	)
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-lite", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to the server subprocess: %v", err)
	}
	defer sess.Close()

	res, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 11 {
		names := make([]string, 0, len(res.Tools))
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		t.Errorf("lite advertised %d tools, want 11: %v", len(res.Tools), names)
	}
	for _, tool := range res.Tools {
		switch tool.Name {
		case "ctfd_notifications", "ctfd_my_team", "ctfd_create_token", "ctfd_score_history":
			t.Errorf("%s should not be registered in lite", tool.Name)
		}
	}
	// The core play loop must still be present.
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, need := range []string{"ctfd_list_challenges", "ctfd_submit_flag", "ctfd_get_hint", "ctfd_my_submissions"} {
		if !got[need] {
			t.Errorf("lite is missing the core tool %s", need)
		}
	}
}

func TestBinaryRejectsBadConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in short mode")
	}
	bin := buildBinary(t)

	cases := []struct {
		name    string
		env     []string
		wantOut string
	}{
		{"no url", []string{"CTFD_TOKEN=ctfd_" + strings.Repeat("a", 64)}, "base URL is required"},
		{"no credentials", []string{"CTFD_URL=https://x.example.com"}, "no credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, bin)
			// A clean environment, so the developer's own CTFD_* vars cannot
			// make this pass or fail spuriously.
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "SystemRoot=" + os.Getenv("SystemRoot")}, tc.env...)
			out, err := cmd.CombinedOutput()

			if err == nil {
				t.Error("expected a non-zero exit for an invalid configuration")
			}
			if !strings.Contains(string(out), tc.wantOut) {
				t.Errorf("output should explain the problem (%q):\n%s", tc.wantOut, out)
			}
		})
	}
}

// buildBinary compiles the server into a temporary directory.
func buildBinary(t *testing.T) string {
	t.Helper()
	name := "ctfd-mcp-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)

	cmd := exec.Command("go", "build", "-o", path, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the server binary: %v\n%s", err, out)
	}
	return path
}

// stubCTFd is a minimal CTFd for the subprocess to talk to. It records
// whether every request arrived correctly authenticated.
type stubCTFd struct {
	*httptest.Server
	mu        chan struct{}
	attempted int
	bad       []string
}

func newStubCTFd(t *testing.T) *stubCTFd {
	t.Helper()
	s := &stubCTFd{mu: make(chan struct{}, 1)}
	s.mu <- struct{}{}

	mux := http.NewServeMux()
	record := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			<-s.mu
			if r.Header.Get("Content-Type") != "application/json" {
				s.bad = append(s.bad, r.Method+" "+r.URL.Path+" (Content-Type "+r.Header.Get("Content-Type")+")")
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Token ctfd_") {
				s.bad = append(s.bad, r.Method+" "+r.URL.Path+" (no token)")
			}
			if r.URL.Path == "/api/v1/challenges/attempt" {
				s.attempted++
			}
			s.mu <- struct{}{}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/v1/users/me", record(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"id":1,"name":"e2e-player","team_id":null}}`))
	}))
	mux.HandleFunc("/api/v1/scoreboard", record(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[{"pos":1,"account_id":1,"account_type":"user","name":"e2e-player","score":10}]}`))
	}))
	mux.HandleFunc("/", record(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
	}))

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *stubCTFd) attempts() int {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	return s.attempted
}

func (s *stubCTFd) badRequests() []string {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	return append([]string(nil), s.bad...)
}

func contentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
