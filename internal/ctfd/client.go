package ctfd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/tjobe4340/ctfd-mcp/internal/redact"
)

// APIPrefix is the CTFd v1 API root, relative to the deployment base URL.
const APIPrefix = "api/v1/"

// Options configures a Client. Zero values fall back to conservative defaults,
// so a Client built from a partially-populated Options is still safe to use.
type Options struct {
	// BaseURL is the CTFd root, with a trailing slash.
	BaseURL *url.URL
	// Token is a CTFd API token. Takes precedence over Session.
	Token string
	// Session is a CTFd session cookie value.
	Session string
	// Username and Password authenticate via CTFd's login form. Call Login
	// after construction to establish the session.
	Username string
	Password string

	UserAgent   string
	Timeout     time.Duration
	MaxRetries  int
	RateLimit   float64
	RateBurst   int
	SubmitRate  float64
	SubmitBurst int
	PerPage     int
	MaxPages    int
	// MaxResponseBytes caps a decoded response body.
	MaxResponseBytes int64
	CacheTTL         time.Duration
	InsecureTLS      bool

	Logger   *slog.Logger
	Redactor *redact.Redactor

	// HTTPClient overrides the constructed client. Tests use this; production
	// callers should leave it nil so transport tuning is applied.
	HTTPClient *http.Client
	// Backoff overrides the retry schedule. Tests use this for determinism.
	Backoff *Backoff
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Client is a CTFd v1 API client.
//
// It is safe for concurrent use. Every request passes through a client-side
// rate limiter, a bounded retry loop with jittered backoff, and a strict
// response-size cap.
type Client struct {
	base   *url.URL
	http   *http.Client
	opts   Options
	log    *slog.Logger
	red    *redact.Redactor
	now    func() time.Time
	bo     Backoff
	limit  *rate.Limiter
	submit *rate.Limiter
	cache  *ttlCache

	// csrf caches the nonce required for unsafe methods under session auth.
	csrfMu    sync.Mutex
	csrfNonce string
	csrfSetAt time.Time

	// loginMu serializes password logins so concurrent tool calls perform one
	// login rather than racing several.
	loginMu  sync.Mutex
	loggedIn bool
}

// NewClient builds a Client from opts.
func NewClient(opts Options) (*Client, error) {
	if opts.BaseURL == nil {
		return nil, errors.New("ctfd: BaseURL is required")
	}
	if opts.Token == "" && opts.Session == "" && opts.Username == "" {
		return nil, errors.New("ctfd: one of Token, Session, or Username+Password is required")
	}

	setDefaults(&opts)

	c := &Client{
		base:   opts.BaseURL,
		opts:   opts,
		log:    opts.Logger,
		red:    opts.Redactor,
		now:    opts.Now,
		limit:  rate.NewLimiter(rate.Limit(opts.RateLimit), opts.RateBurst),
		submit: rate.NewLimiter(rate.Limit(opts.SubmitRate), opts.SubmitBurst),
		cache:  newTTLCache(opts.CacheTTL),
	}
	if opts.Backoff != nil {
		c.bo = *opts.Backoff
	} else {
		c.bo = DefaultBackoff()
	}
	if opts.HTTPClient != nil {
		c.http = opts.HTTPClient
	} else {
		c.http = newHTTPClient(opts)
	}
	c.red.Add(opts.Token)
	c.red.Add(opts.Session)
	c.red.Add(opts.Password)
	return c, nil
}

// NeedsLogin reports whether the client was configured with credentials and
// must call Login before it can authenticate.
func (c *Client) NeedsLogin() bool {
	return c.opts.Token == "" && c.opts.Session == "" && c.opts.Username != ""
}

// Credentials returns the configured login username and password.
func (c *Client) Credentials() (string, string) {
	return c.opts.Username, c.opts.Password
}

func setDefaults(o *Options) {
	if o.UserAgent == "" {
		o.UserAgent = "ctfd-mcp"
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.RateLimit <= 0 {
		o.RateLimit = 5
	}
	if o.RateBurst < 1 {
		o.RateBurst = 10
	}
	if o.SubmitRate <= 0 {
		o.SubmitRate = 0.5
	}
	if o.SubmitBurst < 1 {
		o.SubmitBurst = 1
	}
	if o.PerPage < 1 || o.PerPage > 100 {
		o.PerPage = 50
	}
	if o.MaxPages < 1 {
		o.MaxPages = 20
	}
	if o.MaxResponseBytes < 1 {
		o.MaxResponseBytes = 32 << 20
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Redactor == nil {
		o.Redactor = redact.New()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// newHTTPClient builds a tuned client. http.DefaultClient is deliberately not
// used: it has no timeout, so a hung CTFd instance would wedge a tool call
// until the MCP client gave up.
func newHTTPClient(o Options) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
		// A single MCP server talks to exactly one CTFd host, so idle
		// connections are worth keeping around; the default of 2 per host
		// would force reconnects during a burst of parallel reads.
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   16,
		MaxConnsPerHost:       32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
	}
	if o.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, documented
	}
	// Retain cookies even in token mode. CTFd calls login_user() on every
	// successful token authentication and hands back a session cookie;
	// keeping it lets /files/<location> downloads authenticate by session on
	// instances where challenge_visibility is private and the signed URL token
	// alone is not enough.
	jar, err := cookiejar.New(nil)
	if err != nil {
		// A cookie jar is an optimization, not a requirement.
		jar = nil
	}
	return &http.Client{
		Transport: tr,
		Jar:       jar,
		// No client-level Timeout: each request carries its own context
		// deadline, which lets the retry loop own the overall budget and
		// produces a context error we can classify rather than a bare
		// "Client.Timeout exceeded".
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			// An API call must never follow a redirect. CTFd bounces
			// unauthenticated API requests to /login, and a teams-mode player
			// with no team to /teams, both of which serve HTML. Following
			// either turns a diagnosable 302 into "invalid character '<'".
			// Stopping here lets classify() report it as an auth problem.
			if len(via) > 0 && strings.Contains(via[0].URL.Path, "/"+APIPrefix) {
				return http.ErrUseLastResponse
			}
			// File downloads must still follow redirects: with an S3 storage
			// backend CTFd answers /files/... with a 302 to a presigned URL on
			// another host. Go drops Authorization and Cookie headers on a
			// cross-host redirect, so CTFd credentials are not forwarded.
			return nil
		},
	}
}

// BaseURL returns the configured CTFd root.
func (c *Client) BaseURL() *url.URL { return c.base }

// PerPage returns the configured page size.
func (c *Client) PerPage() int { return c.opts.PerPage }

// MaxPages returns the configured automatic pagination bound.
func (c *Client) MaxPages() int { return c.opts.MaxPages }

// AuthMethod describes how the client authenticates, for diagnostics.
func (c *Client) AuthMethod() string {
	switch {
	case c.opts.Token != "":
		return "api-token"
	case c.opts.Session != "":
		return "session-cookie"
	default:
		return "password-login"
	}
}

// resolve builds an absolute URL for an API-relative path such as
// "challenges" or "challenges/12/solves".
//
// It resolves against BaseURL rather than concatenating strings, so a CTFd
// served under a subdirectory (APPLICATION_ROOT=/ctf) works without special
// cases.
func (c *Client) resolve(apiPath string, q url.Values) (*url.URL, error) {
	rel, err := url.Parse(APIPrefix + strings.TrimPrefix(apiPath, "/"))
	if err != nil {
		return nil, fmt.Errorf("ctfd: bad API path %q: %w", apiPath, err)
	}
	u := c.base.ResolveReference(rel)
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u, nil
}

// ResolveSitePath builds an absolute URL for a non-API path, such as the
// /files/<location> download route.
func (c *Client) ResolveSitePath(sitePath string) (*url.URL, error) {
	rel, err := url.Parse(strings.TrimPrefix(sitePath, "/"))
	if err != nil {
		return nil, fmt.Errorf("ctfd: bad site path %q: %w", sitePath, err)
	}
	return c.base.ResolveReference(rel), nil
}

// request describes a single API call.
type request struct {
	method string
	// path is relative to APIPrefix, e.g. "challenges/1".
	path  string
	query url.Values
	// body, if non-nil, is JSON-encoded as the request body.
	body any
	// idempotent reports whether replaying this request is harmless. Only
	// idempotent requests are retried; a retried flag submission would burn a
	// second attempt against a per-challenge limit and double-count in the
	// organizer's submission log.
	idempotent bool
	// useSubmitLimiter routes this request through the stricter submission
	// bucket in addition to the global one.
	useSubmitLimiter bool
	// cacheKey, when non-empty, enables read-through caching for this request.
	cacheKey string
	// dataOnErrorStatus makes a non-2xx response succeed at this layer when
	// CTFd still returned a usable envelope. Exactly one endpoint needs it:
	// POST /challenges/attempt reports "paused" with 403 and "ratelimited"
	// with 429 while setting success:true, and the caller must see the status
	// string rather than a generic HTTP error.
	dataOnErrorStatus bool
}

// apiResult carries everything a caller may need from one API call.
type apiResult struct {
	Data json.RawMessage
	Meta *Meta
	// Status is the HTTP status code of the final attempt.
	Status int
}

// Meta is the envelope's metadata block.
type Meta struct {
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Pagination mirrors CTFd's pagination metadata. next and prev are null on the
// last and first page respectively, hence the pointers.
type Pagination struct {
	Page    int  `json:"page"`
	Next    *int `json:"next"`
	Prev    *int `json:"prev"`
	Pages   int  `json:"pages"`
	PerPage int  `json:"per_page"`
	Total   int  `json:"total"`
}

// HasNext reports whether another page follows.
func (p *Pagination) HasNext() bool { return p != nil && p.Next != nil && *p.Next > p.Page }

// envelope is the CTFd response wrapper. Every field is decoded lazily so a
// response whose "data" does not match the caller's expectation still yields a
// useful error rather than a decode panic.
type envelope struct {
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
	Errors  json.RawMessage `json:"errors"`
	Message json.RawMessage `json:"message"`
	Meta    *Meta           `json:"meta"`
}

// get issues a GET and decodes the envelope's data into out.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) (*Meta, error) {
	res, err := c.do(ctx, request{
		method:     http.MethodGet,
		path:       path,
		query:      q,
		idempotent: true,
		cacheKey:   cacheKeyFor(path, q),
	}, out)
	return res.Meta, err
}

// do executes a request, applying rate limiting, retries, and envelope
// decoding. out may be nil to discard the payload.
func (c *Client) do(ctx context.Context, req request, out any) (apiResult, error) {
	if req.cacheKey != "" && out != nil {
		if hit, meta, ok := c.cache.get(req.cacheKey); ok {
			if err := json.Unmarshal(hit, out); err == nil {
				c.log.Debug("cache hit", "path", req.path)
				return apiResult{Data: hit, Meta: meta, Status: http.StatusOK}, nil
			}
			// A cached payload that no longer decodes into the caller's type
			// means the caller changed, not the server; drop it silently.
			c.cache.delete(req.cacheKey)
		}
	}

	u, err := c.resolve(req.path, req.query)
	if err != nil {
		return apiResult{}, err
	}

	var bodyBytes []byte
	if req.body != nil {
		bodyBytes, err = json.Marshal(req.body)
		if err != nil {
			return apiResult{}, fmt.Errorf("ctfd: encoding request body for %s: %w", req.path, err)
		}
	}

	res, err := c.roundTrip(ctx, req, u, bodyBytes)
	if err != nil && c.staleNonceRejected(req, err) {
		// CTFd checks the CSRF nonce in a before_request hook, so a rejection
		// happens before the handler runs: no submission was recorded and no
		// attempt was consumed. That makes exactly one retry with a fresh
		// nonce safe even for flag submission, which is otherwise never
		// retried.
		c.log.Debug("refreshing CSRF nonce after a 403 and retrying once", "path", req.path)
		c.ResetCSRF()
		res, err = c.roundTrip(ctx, req, u, bodyBytes)
	}
	if err != nil {
		return res, err
	}

	if req.cacheKey != "" {
		c.cache.set(req.cacheKey, res.Data, res.Meta)
	}

	if out != nil && len(res.Data) > 0 {
		if err := json.Unmarshal(res.Data, out); err != nil {
			return res, &Error{
				Kind:       KindDecode,
				StatusCode: res.Status,
				Method:     req.method,
				Path:       req.path,
				Message:    "response payload did not match the expected shape",
				Body:       truncate(string(res.Data), 512),
				Err:        err,
			}
		}
	}
	return res, nil
}

// staleNonceRejected reports whether a failure looks like CTFd rejecting a
// stale CSRF nonce rather than a genuine authorization problem.
//
// Nonces rotate whenever CTFd regenerates the session, so a long-lived server
// will eventually present an outdated one. The signature is narrow on purpose:
// a bare 403 with no payload, on an unsafe method, under cookie authentication
// which is the only mode that sends a nonce at all. A real 403 from CTFd
// (paused event, hidden scoreboard, unmet prerequisites) carries a message or
// a data block.
func (c *Client) staleNonceRejected(req request, err error) bool {
	if c.opts.Token != "" || isSafeMethod(req.method) {
		return false
	}
	e, ok := AsError(err)
	if !ok || e.StatusCode != http.StatusForbidden {
		return false
	}
	return e.Message == "" && len(e.Fields) == 0
}

// roundTrip runs the rate-limit / send / classify / retry loop and returns the
// raw "data" payload plus metadata.
func (c *Client) roundTrip(ctx context.Context, req request, u *url.URL, body []byte) (apiResult, error) {
	attempts := c.opts.MaxRetries + 1
	if !req.idempotent {
		// Non-idempotent requests get exactly one attempt. This is not a
		// performance choice: CTFd records a failed attempt for a submission
		// even when it answers 429, so a retry would silently consume a
		// second try against a capped challenge.
		attempts = 1
	}

	var lastErr error
	var lastRes apiResult
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			var ra time.Duration
			var hasRA bool
			if e, ok := AsError(lastErr); ok {
				ra, hasRA = e.RetryAfter, e.RetryAfter > 0
			}
			d := retryDelay(c.bo, attempt-1, ra, hasRA)
			c.log.Debug("retrying", "path", req.path, "attempt", attempt+1, "of", attempts, "delay", d.String())
			if err := sleepCtx(ctx, d); err != nil {
				return lastRes, c.ctxError(req, err)
			}
		}

		if err := c.wait(ctx, req); err != nil {
			return lastRes, c.ctxError(req, err)
		}

		res, err := c.attempt(ctx, req, u, body)
		if err == nil {
			return res, nil
		}
		lastErr, lastRes = err, res

		e, ok := AsError(err)
		if !ok || !e.Retryable() {
			return res, err
		}
	}
	return lastRes, lastErr
}

// wait blocks until the client-side rate limiters permit the request.
func (c *Client) wait(ctx context.Context, req request) error {
	if req.useSubmitLimiter {
		if err := c.submit.Wait(ctx); err != nil {
			return err
		}
	}
	return c.limit.Wait(ctx)
}

// attempt performs one HTTP round trip and classifies the outcome.
func (c *Client) attempt(ctx context.Context, req request, u *url.URL, body []byte) (apiResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, req.method, u.String(), rdr)
	if err != nil {
		return apiResult{}, &Error{Kind: KindTransport, Method: req.method, Path: req.path, Err: err}
	}
	if body != nil {
		httpReq.ContentLength = int64(len(body))
		httpReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	// Content-Type must be set on EVERY request, including bodyless GETs.
	//
	// CTFd's tokens() before_request reads the Authorization header only when
	// request.mimetype == "application/json". Without this header Go sends
	// none, CTFd skips token lookup entirely, and the request executes
	// ANONYMOUSLY -- often returning HTTP 200 with only public data rather
	// than a 401. The failure is silent and looks like missing permissions.
	//
	// It must also be the bare literal: CTFd's auth decorators compare
	// request.content_type with exact equality, so "application/json;
	// charset=utf-8" makes them fall through to an HTML login redirect
	// instead of returning a JSON 403.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.opts.UserAgent)
	if err := c.authenticate(ctx, httpReq); err != nil {
		return apiResult{}, err
	}

	start := c.now()
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return apiResult{}, c.transportError(req, err)
	}
	defer drainAndClose(resp.Body)

	c.log.Debug("request",
		"method", req.method,
		"path", req.path,
		"status", resp.StatusCode,
		"duration_ms", c.now().Sub(start).Milliseconds(),
	)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxResponseBytes+1))
	if err != nil {
		return apiResult{Status: resp.StatusCode}, c.transportError(req, fmt.Errorf("reading response body: %w", err))
	}
	if int64(len(raw)) > c.opts.MaxResponseBytes {
		return apiResult{Status: resp.StatusCode}, &Error{
			Kind: KindDecode, StatusCode: resp.StatusCode, Method: req.method, Path: req.path,
			Message: fmt.Sprintf("response exceeded the %d byte limit; narrow the query or raise CTFD_MAX_RESPONSE_BYTES", c.opts.MaxResponseBytes),
		}
	}

	return c.classify(req, resp, raw)
}

// classify turns an HTTP response into either a decoded payload or a typed
// error.
func (c *Client) classify(req request, resp *http.Response, raw []byte) (apiResult, error) {
	retryAfter, hasRetryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
	res := apiResult{Status: resp.StatusCode}

	var env envelope
	decodeErr := json.Unmarshal(raw, &env)
	if decodeErr == nil {
		res.Meta = env.Meta
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if decodeErr != nil {
			return res, &Error{
				Kind: KindDecode, StatusCode: resp.StatusCode, Method: req.method, Path: req.path,
				Message: describeNonJSON(resp, raw),
				Body:    truncate(string(raw), 512),
				Err:     decodeErr,
			}
		}
		// A 2xx with success:false happens on endpoints that report
		// application-level failure in-band.
		if env.Success != nil && !*env.Success {
			return res, c.envelopeError(req, resp.StatusCode, env, raw, retryAfter, hasRetryAfter)
		}
		res.Data = env.Data
		return res, nil
	}

	// Some endpoints answer with a meaningful payload under an error status.
	// When the caller opted in and CTFd sent a well-formed success envelope,
	// hand the payload back instead of an opaque HTTP error.
	if req.dataOnErrorStatus && decodeErr == nil && env.Success != nil && *env.Success && len(env.Data) > 0 {
		res.Data = env.Data
		return res, nil
	}

	// Non-2xx. CTFd usually still returns the JSON envelope; a proxy or a
	// login redirect will not.
	e := &Error{
		Kind:       kindForStatus(resp.StatusCode),
		StatusCode: resp.StatusCode,
		Method:     req.method,
		Path:       req.path,
		Body:       truncate(c.red.String(string(raw)), 512),
	}
	if hasRetryAfter {
		e.RetryAfter = retryAfter
	}
	if decodeErr == nil {
		e.Message = decodeMessage(env.Message)
		e.Fields = decodeFieldErrors(env.Errors)
		// Some CTFd endpoints carry the real reason inside data.status /
		// data.message even on an error status (notably challenge attempts
		// during a pause or after the CTF ends).
		if e.Message == "" {
			if s := decodeStatusMessage(env.Data); s != "" {
				e.Message = s
			}
		}
	} else if looksLikeHTML(raw) {
		e.Kind = KindDecode
		e.Message = describeNonJSON(resp, raw)
	}
	// A redirect to the login page is an authentication problem, whatever
	// status the proxy attached to it.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); strings.Contains(loc, "login") {
			e.Kind = KindAuth
			e.Message = "CTFd redirected to the login page, which means the request was not authenticated"
		}
	}
	return res, e
}

func (c *Client) envelopeError(req request, status int, env envelope, raw []byte, ra time.Duration, hasRA bool) *Error {
	e := &Error{
		Kind:       KindUnexpected,
		StatusCode: status,
		Method:     req.method,
		Path:       req.path,
		Message:    decodeMessage(env.Message),
		Fields:     decodeFieldErrors(env.Errors),
		Body:       truncate(c.red.String(string(raw)), 512),
	}
	if hasRA {
		e.RetryAfter = ra
		e.Kind = KindRateLimited
	}
	if len(e.Fields) > 0 {
		e.Kind = KindValidation
	}
	if e.Message == "" && len(e.Fields) == 0 {
		e.Message = "CTFd reported failure without a reason"
	}
	return e
}

func (c *Client) transportError(req request, err error) error {
	kind := KindTransport
	if errors.Is(err, context.DeadlineExceeded) {
		kind = KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		kind = KindTimeout
	}
	// A transport failure is only worth repeating when it looks transient.
	// A bad certificate or an NXDOMAIN will fail identically every time, and
	// retrying it just delays a clear error message.
	return &Error{
		Kind:    kind,
		Method:  req.method,
		Path:    req.path,
		Err:     err,
		NoRetry: !isRetryableNetErr(err),
	}
}

func (c *Client) ctxError(req request, err error) error {
	kind := KindTimeout
	if errors.Is(err, context.Canceled) {
		kind = KindTransport
	}
	return &Error{Kind: kind, Method: req.method, Path: req.path, Err: err}
}

// authenticate attaches credentials to req.
func (c *Client) authenticate(ctx context.Context, req *http.Request) error {
	if c.opts.Token != "" {
		// CTFd accepts "Authorization: Token <token>" for API tokens. Its
		// presence also makes CTFd skip CSRF entirely, so no nonce is needed.
		req.Header.Set("Authorization", "Token "+c.opts.Token)
		return nil
	}

	// An explicitly configured cookie is attached by hand; a cookie obtained
	// by Login already lives in the jar and is attached by net/http.
	if c.opts.Session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: c.opts.Session})
	}
	if isSafeMethod(req.Method) {
		return nil
	}
	// Cookie-authenticated writes must carry the session's CSRF nonce.
	nonce, err := c.csrfToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("CSRF-Token", nonce)
	return nil
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// drainAndClose consumes the remainder of a response body so the underlying
// connection can be returned to the idle pool, then closes it. Without the
// drain, a partially-read body forces a new TCP+TLS handshake on the next
// request.
func drainAndClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 64<<10))
	_ = rc.Close()
}

// decodeMessage handles CTFd's inconsistent "message" field, which is a string
// on most endpoints but occasionally a list of strings.
func decodeMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return strings.Join(list, "; ")
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		if v, ok := obj["message"].(string); ok {
			return v
		}
	}
	return strings.TrimSpace(string(raw))
}

// decodeFieldErrors handles CTFd's "errors" field, which marshmallow renders
// as {"field": ["msg", ...]} but which some handlers emit as a bare list.
func decodeFieldErrors(raw json.RawMessage) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string][]string
	if err := json.Unmarshal(raw, &m); err == nil && len(m) > 0 {
		return m
	}
	var mixed map[string]any
	if err := json.Unmarshal(raw, &mixed); err == nil && len(mixed) > 0 {
		out := make(map[string][]string, len(mixed))
		for k, v := range mixed {
			switch t := v.(type) {
			case string:
				out[k] = []string{t}
			case []any:
				for _, item := range t {
					out[k] = append(out[k], fmt.Sprint(item))
				}
			default:
				out[k] = []string{fmt.Sprint(t)}
			}
		}
		return out
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		return map[string][]string{"_": list}
	}
	return nil
}

// decodeStatusMessage pulls data.message out of an error envelope.
func decodeStatusMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var d struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return ""
	}
	switch {
	case d.Message != "" && d.Status != "":
		return fmt.Sprintf("%s (%s)", d.Message, d.Status)
	case d.Message != "":
		return d.Message
	case d.Status != "":
		return d.Status
	default:
		return ""
	}
}

func looksLikeHTML(b []byte) bool {
	s := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 256)])))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<title>")
}

// describeNonJSON produces an actionable message when the body is not the API
// envelope, which is the single most common misconfiguration symptom.
func describeNonJSON(resp *http.Response, raw []byte) string {
	ct := resp.Header.Get("Content-Type")
	switch {
	case looksLikeHTML(raw):
		return fmt.Sprintf("expected a JSON API response but received an HTML page (Content-Type %q); the URL may not point at a CTFd API root, or the request was redirected to a login or error page", ct)
	case len(raw) == 0:
		return "the server returned an empty body where a JSON API response was expected"
	default:
		return fmt.Sprintf("expected a JSON API response but received Content-Type %q", ct)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}
