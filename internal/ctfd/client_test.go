package ctfd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at ts with deterministic backoff, so
// retry tests do not depend on wall-clock jitter.
func newTestClient(t *testing.T, ts *httptest.Server, mutate func(*Options)) *Client {
	t.Helper()
	base, err := url.Parse(ts.URL + "/")
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	opts := Options{
		BaseURL:    base,
		Token:      "ctfd_testtoken0000000000000000",
		HTTPClient: ts.Client(),
		Timeout:    5 * time.Second,
		MaxRetries: 2,
		RateLimit:  1000,
		RateBurst:  1000,
		SubmitRate: 1000, SubmitBurst: 1000,
		PerPage:  50,
		MaxPages: 10,
		// Zero backoff keeps retry tests fast; jitter is exercised separately.
		Backoff: &Backoff{Base: 0, Max: 0, Rand: func() float64 { return 0 }},
	}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestAuthorizationHeader(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		writeJSON(w, 200, `{"success":true,"data":{"id":1,"name":"me"}}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	if _, err := c.Me(context.Background()); err != nil {
		t.Fatalf("Me: %v", err)
	}
	if want := "Token ctfd_testtoken0000000000000000"; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

// TestContentTypeIsSetOnEveryRequest guards a silent-failure mode in CTFd.
//
// CTFd's tokens() before_request hook reads the Authorization header only when
// request.mimetype == "application/json". A bodyless GET without this header
// is processed ANONYMOUSLY -- CTFd returns 200 with public data instead of
// 401, so the bug looks like missing permissions rather than broken auth.
//
// The value must also be the bare literal: CTFd's auth decorators compare
// request.content_type for exact equality, so appending "; charset=utf-8"
// turns would-be JSON 403s into HTML login redirects.
func TestContentTypeIsSetOnEveryRequest(t *testing.T) {
	type seen struct{ method, contentType, auth string }
	var got []seen

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.Method, r.Header.Get("Content-Type"), r.Header.Get("Authorization")})
		if r.Method == http.MethodPost {
			writeJSON(w, 200, `{"success":true,"data":{"status":"incorrect","message":"no"}}`)
			return
		}
		writeJSON(w, 200, `{"success":true,"data":[]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	ctx := context.Background()

	if _, err := c.Challenges(ctx, ChallengeFilter{}); err != nil {
		t.Fatalf("Challenges: %v", err)
	}
	if _, err := c.Attempt(ctx, 1, "flag{x}"); err != nil {
		t.Fatalf("Attempt: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(got))
	}
	for _, s := range got {
		if s.contentType != "application/json" {
			t.Errorf("%s request sent Content-Type %q, want exactly \"application/json\"; "+
				"anything else makes CTFd ignore the token and run the request anonymously",
				s.method, s.contentType)
		}
		if s.auth == "" {
			t.Errorf("%s request carried no Authorization header", s.method)
		}
	}
}

func TestSubdirectoryDeployment(t *testing.T) {
	// A CTFd behind APPLICATION_ROOT=/ctf must have its prefix preserved
	// rather than replaced by the API path.
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeJSON(w, 200, `{"success":true,"data":[]}`)
	}))
	defer ts.Close()

	base, _ := url.Parse(ts.URL + "/ctf/")
	c := newTestClient(t, ts, func(o *Options) { o.BaseURL = base })

	if _, err := c.Challenges(context.Background(), ChallengeFilter{}); err != nil {
		t.Fatalf("Challenges: %v", err)
	}
	if want := "/ctf/api/v1/challenges"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantKind Kind
		wantMsg  string
	}{
		{"unauthorized", 401, `{"success":false,"message":"token expired"}`, KindAuth, "token expired"},
		{"forbidden", 403, `{"success":false,"message":"hidden"}`, KindForbidden, "hidden"},
		{"not found", 404, `{"success":false}`, KindNotFound, ""},
		{"validation", 400, `{"success":false,"errors":{"submission":["required"]}}`, KindValidation, ""},
		{"rate limited", 429, `{"success":false,"message":"slow down"}`, KindRateLimited, "slow down"},
		{"server error", 500, `{"success":false}`, KindServer, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, tc.body)
			}))
			defer ts.Close()

			// No retries, so a 429/500 surfaces immediately.
			c := newTestClient(t, ts, func(o *Options) { o.MaxRetries = 0 })
			_, err := c.Me(context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}
			e, ok := AsError(err)
			if !ok {
				t.Fatalf("error was not a *Error: %T", err)
			}
			if e.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", e.Kind, tc.wantKind)
			}
			if tc.wantMsg != "" && e.Message != tc.wantMsg {
				t.Errorf("Message = %q, want %q", e.Message, tc.wantMsg)
			}
			if e.Hint() == "" {
				t.Error("expected a non-empty Hint for an operator-visible failure")
			}
		})
	}
}

func TestValidationFieldErrorsAcceptStringsAndLists(t *testing.T) {
	// CTFd is inconsistent: /unlocks returns errors values as bare strings
	// while marshmallow validation returns lists. Both must decode.
	cases := map[string]string{
		"list":   `{"success":false,"errors":{"score":["not enough points"]}}`,
		"string": `{"success":false,"errors":{"score":"not enough points"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 400, body)
			}))
			defer ts.Close()

			c := newTestClient(t, ts, nil)
			_, err := c.UnlockHint(context.Background(), 3)
			e, ok := AsError(err)
			if !ok {
				t.Fatalf("expected *Error, got %v", err)
			}
			if e.Kind != KindValidation {
				t.Errorf("Kind = %q, want validation", e.Kind)
			}
			if got := e.Fields["score"]; len(got) != 1 || got[0] != "not enough points" {
				t.Errorf("Fields[score] = %v, want [not enough points]", got)
			}
		})
	}
}

func TestNonJSONResponseIsActionable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><title>Login</title></html>"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	_, err := c.Me(context.Background())
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("expected *Error, got %v", err)
	}
	if e.Kind != KindDecode {
		t.Errorf("Kind = %q, want decode", e.Kind)
	}
	if !strings.Contains(e.Message, "HTML") {
		t.Errorf("message should mention HTML, got %q", e.Message)
	}
}

func TestHTMLNotFoundPreservesNotFoundKind(t *testing.T) {
	// Older CTFd versions use Flask's default HTML 404 for API routes that did
	// not exist yet. Optional-feature callers need the semantic 404 to select a
	// fallback, while the message should still explain the unexpected HTML.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><title>Not Found</title></html>"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	_, err := c.MySubmissions(context.Background(), 0)
	if !IsNotFound(err) {
		t.Fatalf("HTML 404 should remain not-found, got %v", err)
	}
	if !strings.Contains(err.Error(), "HTML") {
		t.Errorf("error should still diagnose the HTML response: %v", err)
	}
}

func TestRetriesTransientFailuresThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			writeJSON(w, 503, `{"success":false,"message":"unavailable"}`)
			return
		}
		writeJSON(w, 200, `{"success":true,"data":{"id":7,"name":"me"}}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	me, err := c.Me(context.Background())
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.ID != 7 {
		t.Errorf("ID = %d, want 7", me.ID)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("made %d calls, want 3", got)
	}
}

func TestDoesNotRetryNonRetryableStatus(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, 404, `{"success":false}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	if _, err := c.Challenge(context.Background(), 1); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d calls, want 1 (404 must not be retried)", got)
	}
}

// TestFlagSubmissionIsNeverRetried guards the single most consequential
// behavior in this client. CTFd records a failed attempt even when it answers
// 429, so a retried submission silently burns a second attempt against a
// capped challenge.
func TestFlagSubmissionIsNeverRetried(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, 429, `{"success":true,"data":{"status":"ratelimited","message":"You're submitting flags too fast. Slow down."}}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, func(o *Options) { o.MaxRetries = 5 })
	res, err := c.Attempt(context.Background(), 1, "flag{x}")
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("made %d submissions, want exactly 1", got)
	}
	if res.Status != AttemptRateLimited {
		t.Errorf("Status = %q, want ratelimited", res.Status)
	}
	if !res.ConsumedAttempt() {
		t.Error("a rate-limited submission must be reported as consuming an attempt")
	}
}

func TestAttemptStatusesAcrossHTTPCodes(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantStatus AttemptStatus
		wantSolved bool
		wantSpent  bool
	}{
		{"correct", 200, `{"success":true,"data":{"status":"correct","message":"Correct"}}`, AttemptCorrect, true, false},
		{"incorrect", 200, `{"success":true,"data":{"status":"incorrect","message":"Incorrect"}}`, AttemptIncorrect, false, true},
		{"already solved", 200, `{"success":true,"data":{"status":"already_solved","message":"You already solved this"}}`, AttemptAlreadySolved, true, false},
		{"paused", 403, `{"success":true,"data":{"status":"paused","message":"CTF is paused"}}`, AttemptPaused, false, false},
		{"out of tries", 403, `{"success":true,"data":{"status":"incorrect","message":"You have 0 tries remaining"}}`, AttemptIncorrect, false, true},
		{"ratelimited", 429, `{"success":true,"data":{"status":"ratelimited","message":"Slow down"}}`, AttemptRateLimited, false, true},
		{"unauthenticated", 403, `{"success":true,"data":{"status":"authentication_required"}}`, AttemptAuthRequired, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decoding request body: %v", err)
				}
				if body["challenge_id"] != float64(42) {
					t.Errorf("challenge_id = %v, want 42", body["challenge_id"])
				}
				if body["submission"] != "flag{test}" {
					t.Errorf("submission = %v, want flag{test}", body["submission"])
				}
				writeJSON(w, tc.status, tc.body)
			}))
			defer ts.Close()

			c := newTestClient(t, ts, nil)
			res, err := c.Attempt(context.Background(), 42, "flag{test}")
			if err != nil {
				t.Fatalf("Attempt: %v", err)
			}
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", res.Status, tc.wantStatus)
			}
			if res.Solved() != tc.wantSolved {
				t.Errorf("Solved() = %v, want %v", res.Solved(), tc.wantSolved)
			}
			if res.ConsumedAttempt() != tc.wantSpent {
				t.Errorf("ConsumedAttempt() = %v, want %v", res.ConsumedAttempt(), tc.wantSpent)
			}
			if res.HTTPStatus != tc.status {
				t.Errorf("HTTPStatus = %d, want %d", res.HTTPStatus, tc.status)
			}
		})
	}
}

func TestRetryAfterIsHonored(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, 429, `{"success":false,"message":"slow down"}`)
			return
		}
		writeJSON(w, 200, `{"success":true,"data":[]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	if _, err := c.Challenges(context.Background(), ChallengeFilter{}); err != nil {
		t.Fatalf("Challenges: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d calls, want 2", got)
	}
}

func TestPaginationFollowsPagesAndReportsTruncation(t *testing.T) {
	const perPage = 2
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if got := r.URL.Query().Get("per_page"); got != fmt.Sprint(perPage) {
			t.Errorf("per_page = %q, want %d", got, perPage)
		}
		switch page {
		case "1":
			writeJSON(w, 200, `{"success":true,"data":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"meta":{"pagination":{"page":1,"next":2,"prev":null,"pages":3,"per_page":2,"total":6}}}`)
		case "2":
			writeJSON(w, 200, `{"success":true,"data":[{"id":3,"name":"c"},{"id":4,"name":"d"}],"meta":{"pagination":{"page":2,"next":3,"prev":1,"pages":3,"per_page":2,"total":6}}}`)
		default:
			writeJSON(w, 200, `{"success":true,"data":[{"id":5,"name":"e"},{"id":6,"name":"f"}],"meta":{"pagination":{"page":3,"next":null,"prev":2,"pages":3,"per_page":2,"total":6}}}`)
		}
	}))
	defer ts.Close()

	t.Run("follows every page", func(t *testing.T) {
		c := newTestClient(t, ts, func(o *Options) { o.PerPage = perPage; o.MaxPages = 10 })
		users, truncated, err := c.Users(context.Background(), AccountFilter{})
		if err != nil {
			t.Fatalf("Users: %v", err)
		}
		if len(users) != 6 {
			t.Errorf("got %d users, want 6", len(users))
		}
		if truncated {
			t.Error("truncated = true, want false when all pages were read")
		}
	})

	t.Run("reports truncation at the page cap", func(t *testing.T) {
		c := newTestClient(t, ts, func(o *Options) { o.PerPage = perPage; o.MaxPages = 2 })
		users, truncated, err := c.Users(context.Background(), AccountFilter{})
		if err != nil {
			t.Fatalf("Users: %v", err)
		}
		if len(users) != 4 {
			t.Errorf("got %d users, want 4", len(users))
		}
		if !truncated {
			t.Error("truncated = false, want true when the page cap stopped the walk")
		}
	})
}

func TestCacheServesRepeatReadsAndWritesInvalidate(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSON(w, 200, `{"success":true,"data":{"status":"incorrect","message":"nope"}}`)
			return
		}
		calls.Add(1)
		writeJSON(w, 200, `{"success":true,"data":[{"id":1,"name":"a","category":"web","value":100}]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, func(o *Options) { o.CacheTTL = time.Minute })
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.Challenges(ctx, ChallengeFilter{}); err != nil {
			t.Fatalf("Challenges: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d GETs, want 1 (repeat reads should hit the cache)", got)
	}

	// A submission changes solve state, so cached reads must be dropped.
	if _, err := c.Attempt(ctx, 1, "flag{x}"); err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if _, err := c.Challenges(ctx, ChallengeFilter{}); err != nil {
		t.Fatalf("Challenges: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d GETs, want 2 (a submission must invalidate the cache)", got)
	}
}

func TestResponseSizeCapRejectsOversizedBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"success":true,"data":"` + strings.Repeat("A", 5000) + `"}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, func(o *Options) { o.MaxResponseBytes = 1024 })
	_, err := c.Me(context.Background())
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("expected *Error, got %v", err)
	}
	if !strings.Contains(e.Message, "limit") {
		t.Errorf("message should explain the size limit, got %q", e.Message)
	}
}

func TestScoreboardTopDecodesPositionKeyedObject(t *testing.T) {
	// CTFd keys this response by stringified rank rather than returning an
	// array, and Go map iteration would otherwise scramble the order.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":{
			"2":{"id":20,"name":"second","score":50,"solves":[{"challenge_id":1,"account_id":20,"value":50,"date":"2026-01-01T10:00:00"}]},
			"1":{"id":10,"name":"first","score":100,"solves":[{"challenge_id":null,"account_id":10,"value":100,"date":"2026-01-01T09:00:00"}]},
			"3":{"id":30,"name":"third","score":10,"solves":[]}
		}}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	got, err := c.ScoreboardTop(context.Background(), 3)
	if err != nil {
		t.Fatalf("ScoreboardTop: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Name != want {
			t.Errorf("entry %d = %q, want %q (entries must be sorted by rank)", i, got[i].Name, want)
		}
		if got[i].Pos != i+1 {
			t.Errorf("entry %d Pos = %d, want %d", i, got[i].Pos, i+1)
		}
	}
	if !got[0].Solves[0].IsAward() {
		t.Error("a null challenge_id should be reported as an award")
	}
	if got[1].Solves[0].IsAward() {
		t.Error("a solve with a challenge_id should not be an award")
	}
}

func TestChallengeDetailDropsRenderedView(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":{"id":1,"name":"c","view":"<div>`+strings.Repeat("x", 2000)+`</div>","description":"desc","solves":null}}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	d, err := c.Challenge(context.Background(), 1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if d.View != "" {
		t.Error("the rendered HTML view should be discarded before it reaches a caller")
	}
	if d.Solves != nil {
		t.Error("a null solve count must stay nil to distinguish 'hidden' from zero")
	}
}

func TestInvalidSearchFieldIsRejectedBeforeSending(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should have been made")
		writeJSON(w, 200, `{"success":true,"data":[]}`)
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	_, err := c.Challenges(context.Background(), ChallengeFilter{Q: "x", Field: "flag"})
	if err == nil {
		t.Fatal("expected an error for an invalid search field")
	}
	if !strings.Contains(err.Error(), "invalid search field") {
		t.Errorf("error = %q, want it to name the invalid field", err)
	}
}

func TestContextCancellationIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.Me(ctx); err == nil {
		t.Fatal("expected a timeout error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d calls, want 1 (a cancelled context must stop retries)", got)
	}
}
