package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/config"
	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
	"github.com/tjobe4340/ctfd-mcp/internal/redact"
)

// fakeCTFd361 serves payloads shaped exactly as CTFd 3.6.1 emits them, which
// differ from 3.7/3.8 in ways that would silently corrupt output if the client
// assumed the newer shapes:
//
//   - A locked hint in challenge detail is {id, cost} with NO title; 3.7 added
//     the title.
//   - Scoreboard entries carry no bracket_id or bracket_name; brackets arrived
//     in 3.7.
//   - Challenge detail has no attribution; that arrived in 3.7.
//   - /challenges/{id}/solution, /challenges/{id}/ratings, and
//     /users/me/submissions do not exist at all and 404.
//
// Auth and CSRF gating is byte-identical to 3.7.7, so it is not re-tested here.
type fakeCTFd361 struct {
	*httptest.Server
	submissions atomic.Int32
	unknownHits atomic.Int32
}

func newFakeCTFd361(t *testing.T) *fakeCTFd361 {
	t.Helper()
	f := &fakeCTFd361{}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		// No bracket_id in 3.6.1.
		writeJSON(w, 200, `{"success":true,"data":{"id":9,"name":"player1","email":"p@example.com","country":"US","affiliation":"Acme","website":"","team_id":null}}`)
	})
	mux.HandleFunc("/api/v1/challenges", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":[
			{"id":1,"type":"standard","name":"Baby RSA","value":100,"category":"crypto","solves":12,"solved_by_me":false,"tags":[{"value":"rsa"}],"template":"/plugins/x/view.html","script":"/plugins/x/view.js"}
		]}`)
	})
	mux.HandleFunc("/api/v1/challenges/1", func(w http.ResponseWriter, r *http.Request) {
		// 3.6.1 detail: no attribution, and the locked hint has no title.
		writeJSON(w, 200, `{"success":true,"data":{
			"id":1,"name":"Baby RSA","value":100,"description":"Decrypt this.","connection_info":"nc x 1337",
			"next_id":null,"category":"crypto","state":"visible","max_attempts":3,"type":"standard",
			"type_data":{"id":"standard","name":"standard"},
			"solves":12,"solved_by_me":false,"attempts":1,
			"files":["/files/abc/chal.zip?token=sig"],"tags":["rsa"],
			"hints":[{"id":5,"cost":10},{"id":6,"cost":0}],
			"view":"<div>rendered</div>"
		}}`)
	})
	mux.HandleFunc("/api/v1/challenges/attempt", func(w http.ResponseWriter, r *http.Request) {
		f.submissions.Add(1)
		writeJSON(w, 200, `{"success":true,"data":{"status":"correct","message":"Correct!"}}`)
	})
	mux.HandleFunc("/api/v1/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		// No bracket fields at all in 3.6.1.
		writeJSON(w, 200, `{"success":true,"data":[
			{"pos":1,"account_id":3,"account_type":"user","oauth_id":null,"name":"ace","score":500},
			{"pos":2,"account_id":9,"account_type":"user","oauth_id":null,"name":"player1","score":150}
		]}`)
	})
	mux.HandleFunc("/api/v1/scoreboard/top/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":{
			"1":{"id":3,"account_url":"/users/3","name":"ace","score":500,"solves":[{"challenge_id":1,"account_id":3,"team_id":null,"user_id":3,"value":100,"date":"2026-08-01T10:00:00"}]}
		}}`)
	})
	mux.HandleFunc("/api/v1/hints/5", func(w http.ResponseWriter, r *http.Request) {
		// Locked: 3.6.1 HintSchema locked view has no content.
		writeJSON(w, 200, `{"success":true,"data":{"id":5,"type":"standard","challenge_id":1,"cost":10}}`)
	})
	mux.HandleFunc("/api/v1/users/me/solves", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":[{"id":1,"challenge_id":1,"date":"2026-08-01T09:00:00","type":"correct","challenge":{"id":1,"name":"Baby RSA","category":"crypto","value":100}}]}`)
	})
	mux.HandleFunc("/api/v1/users/me/fails", func(w http.ResponseWriter, r *http.Request) {
		// 3.6.1 has this route; only /users/me/submissions is 3.8-only.
		writeJSON(w, 200, `{"success":true,"data":[{"id":2,"challenge_id":1,"date":"2026-08-01T08:00:00","type":"incorrect","challenge":{"id":1,"name":"Baby RSA","category":"crypto","value":100}}]}`)
	})
	mux.HandleFunc("/api/v1/users/me/awards", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":[]}`)
	})
	mux.HandleFunc("/api/v1/notifications", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":[{"id":1,"title":"Welcome","content":"Good luck","date":"2026-08-01T08:00:00"}]}`)
	})
	mux.HandleFunc("/api/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":[{"id":1,"type":"user","created":"2026-07-01T00:00:00","expiration":"2099-01-01T00:00:00","description":"mine"}]}`)
	})

	// Everything else 404s, exactly as 3.6.1 does for routes it never had.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.unknownHits.Add(1)
		writeJSON(w, 404, `{"success":false}`)
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func connect361(t *testing.T, f *fakeCTFd361) *mcp.ClientSession {
	t.Helper()
	base, err := url.Parse(f.URL + "/")
	if err != nil {
		t.Fatalf("parsing URL: %v", err)
	}
	red := redact.New(testToken)
	client, err := ctfd.NewClient(ctfd.Options{
		BaseURL: base, Token: testToken, HTTPClient: f.Client(),
		Timeout: 5 * time.Second, RateLimit: 1000, RateBurst: 1000,
		SubmitRate: 1000, SubmitBurst: 1000, PerPage: 50, MaxPages: 5,
		Redactor: red,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s := New(Deps{
		Client:      client,
		Config:      &config.Config{BaseURL: base, DownloadDir: t.TempDir(), MaxDownloadBytes: 1 << 20},
		Redactor:    red,
		AllowSubmit: true,
	})
	return connect(t, s)
}

func TestCTFd361ReadsWork(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	t.Run("whoami without brackets", func(t *testing.T) {
		text, res := callText(t, sess, "ctfd_whoami", nil)
		if res.IsError {
			t.Fatalf("ctfd_whoami failed: %s", text)
		}
		if !strings.Contains(text, "player1") || !strings.Contains(text, "Rank: 2") {
			t.Errorf("identity and rank should resolve on 3.6.1:\n%s", text)
		}
	})

	t.Run("challenge list", func(t *testing.T) {
		text, res := callText(t, sess, "ctfd_list_challenges", nil)
		if res.IsError {
			t.Fatalf("ctfd_list_challenges failed: %s", text)
		}
		if !strings.Contains(text, "Baby RSA") || !strings.Contains(text, "rsa") {
			t.Errorf("challenge and its tags should render:\n%s", text)
		}
	})

	t.Run("scoreboard renders without bracket fields", func(t *testing.T) {
		text, res := callText(t, sess, "ctfd_scoreboard", nil)
		if res.IsError {
			t.Fatalf("ctfd_scoreboard failed: %s", text)
		}
		if !strings.Contains(text, "<-- you") {
			t.Errorf("the caller should still be identified:\n%s", text)
		}
		// An absent bracket must not surface as a literal "null".
		if strings.Contains(strings.ToLower(text), "null") {
			t.Errorf("a missing bracket leaked as null:\n%s", text)
		}
	})

	t.Run("score history", func(t *testing.T) {
		text, res := callText(t, sess, "ctfd_score_history", map[string]any{"count": 1})
		if res.IsError {
			t.Fatalf("ctfd_score_history failed: %s", text)
		}
		if !strings.Contains(text, "ace") {
			t.Errorf("timeline should render:\n%s", text)
		}
	})

	t.Run("progress and notifications", func(t *testing.T) {
		text, res := callText(t, sess, "ctfd_my_progress", nil)
		if res.IsError {
			t.Fatalf("ctfd_my_progress failed: %s", text)
		}
		if !strings.Contains(text, "Solves: 1") {
			t.Errorf("solves should count:\n%s", text)
		}
		text, res = callText(t, sess, "ctfd_notifications", nil)
		if res.IsError {
			t.Fatalf("ctfd_notifications failed: %s", text)
		}
		if !strings.Contains(text, "Welcome") {
			t.Errorf("announcement should render:\n%s", text)
		}
	})
}

// TestCTFd361TitlelessLockedHint covers the one 3.6.1 response shape that
// would otherwise render as a stray placeholder: a locked hint carries only an
// id and a cost, with no title field at all.
func TestCTFd361TitlelessLockedHint(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	text, res := callText(t, sess, "ctfd_get_challenge", map[string]any{"challenge_id": 1})
	if res.IsError {
		t.Fatalf("ctfd_get_challenge failed: %s", text)
	}
	if !strings.Contains(text, "LOCKED, costs 10 points") {
		t.Errorf("the locked hint and its price should show:\n%s", text)
	}
	if strings.Contains(text, "(no title)") {
		t.Errorf("a titleless hint should omit the line, not print a placeholder:\n%s", text)
	}
	// A zero-cost hint still reports as locked in challenge detail on every
	// 3.x; the free-hint shortcut lives only in /api/v1/hints/{id}.
	if !strings.Contains(text, "Hint 6") {
		t.Errorf("the free hint should still be listed:\n%s", text)
	}
	// Attribution is absent in 3.6.1 and must not render as an empty field.
	if strings.Contains(text, "Author:") {
		t.Errorf("no author line should appear when attribution is absent:\n%s", text)
	}
}

func TestCTFd361SubmitFlagWorks(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	text, res := callText(t, sess, "ctfd_submit_flag", map[string]any{"challenge_id": 1, "flag": "flag{x}"})
	if res.IsError {
		t.Fatalf("submission failed on 3.6.1: %s", text)
	}
	if !strings.Contains(text, "CORRECT") {
		t.Errorf("expected a correct verdict:\n%s", text)
	}
	if f.submissions.Load() != 1 {
		t.Errorf("expected exactly 1 submission, got %d", f.submissions.Load())
	}
}

// TestCTFd361NewerFeaturesDegrade proves the 3.8-only tools explain themselves
// on 3.6.1 rather than surfacing a bare 404.
func TestCTFd361NewerFeaturesDegrade(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	// ctfd_my_submissions is deliberately absent: rather than reporting a
	// version requirement, it falls back to solves and fails, which 3.6.1 does
	// expose. That is covered by TestCTFd361SubmissionHistoryFallsBack.
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"ctfd_get_solution", map[string]any{"challenge_id": 1}},
		{"ctfd_rate_challenge", map[string]any{"challenge_id": 1, "rating": "up"}},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			text, res := callText(t, sess, c.tool, c.args)
			if res.IsError {
				t.Fatalf("%s should explain, not error: %s", c.tool, text)
			}
			if !strings.Contains(text, "3.8") {
				t.Errorf("%s should name the version requirement:\n%s", c.tool, text)
			}
			// It must also point somewhere useful rather than dead-ending.
			if !strings.Contains(strings.ToLower(text), "ctfd_my_progress") &&
				!strings.Contains(strings.ToLower(text), "does not exist") {
				t.Logf("%s output: %s", c.tool, text)
			}
		})
	}
}

// TestCTFd361SubmissionHistoryFallsBack proves that seeing what you already
// tried works even on a CTFd with no /users/me/submissions route at all.
func TestCTFd361SubmissionHistoryFallsBack(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	text, res := callText(t, sess, "ctfd_my_submissions", nil)
	if res.IsError {
		t.Fatalf("ctfd_my_submissions should fall back on 3.6.1, not fail: %s", text)
	}
	// One solve and one failed attempt, both on challenge 1.
	if !strings.Contains(text, "CORRECT") {
		t.Errorf("the solve should appear:\n%s", text)
	}
	if !strings.Contains(text, "wrong") {
		t.Errorf("the failed attempt should appear:\n%s", text)
	}
	// Newest first: the 09:00 solve must precede the 08:00 failure.
	if strings.Index(text, "CORRECT") > strings.Index(text, "wrong") {
		t.Errorf("entries should be newest first:\n%s", text)
	}
	if strings.Contains(text, "3.8") {
		t.Errorf("should not report a version requirement now that it falls back:\n%s", text)
	}
}

func TestCTFd361TokensWork(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	// Token management is @authed_only in 3.6.1 exactly as in 3.7/3.8.
	text, res := callText(t, sess, "ctfd_list_tokens", nil)
	if res.IsError {
		t.Fatalf("ctfd_list_tokens failed on 3.6.1: %s", text)
	}
	if !strings.Contains(text, "mine") {
		t.Errorf("the token should be listed:\n%s", text)
	}
}

func TestCTFd361LockedHintViaGetHint(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	text, res := callText(t, sess, "ctfd_get_hint", map[string]any{"hint_id": 5})
	if res.IsError {
		t.Fatalf("ctfd_get_hint failed: %s", text)
	}
	if !strings.Contains(text, "LOCKED") {
		t.Errorf("hint 5 costs points and should report as locked:\n%s", text)
	}
	if strings.Contains(text, "content") && strings.Contains(text, "untrusted") {
		t.Errorf("no content should be shown for a locked hint:\n%s", text)
	}
}

// Guard against a fixture that silently stops covering anything: if every
// request 404s, the tests above would pass vacuously for the wrong reason.
func TestCTFd361FixtureActuallyServes(t *testing.T) {
	f := newFakeCTFd361(t)
	sess := connect361(t, f)

	if _, res := callText(t, sess, "ctfd_whoami", nil); res.IsError {
		t.Fatal("the fixture should serve /users/me")
	}
	ctx := context.Background()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "ctfd_list_challenges"}); err != nil {
		t.Fatalf("the fixture should serve /challenges: %v", err)
	}
}
