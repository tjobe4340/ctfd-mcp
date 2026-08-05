package ctfd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// EnsureLogin establishes a session if the client is configured with a
// username and password and does not already have one.
//
// It is safe to call before every operation: once a session exists it returns
// immediately, and concurrent callers are serialized so a burst of parallel
// tool calls performs one login rather than several.
func (c *Client) EnsureLogin(ctx context.Context) error {
	if !c.NeedsLogin() {
		return nil
	}
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if c.loggedIn {
		return nil
	}
	if _, err := c.loginLocked(ctx, c.opts.Username, c.opts.Password); err != nil {
		return err
	}
	return nil
}

// LoggedIn reports whether a password login has succeeded.
func (c *Client) LoggedIn() bool {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	return c.loggedIn
}

// Login authenticates with a username (or email) and password, establishing a
// session cookie for subsequent requests.
//
// The flow mirrors what a browser does, because CTFd's login is an HTML form
// view rather than an API endpoint:
//
//  1. GET /login, which sets a session cookie and embeds a CSRF nonce.
//  2. POST /login as application/x-www-form-urlencoded with name, password,
//     and that nonce in a form field. CTFd checks the nonce from the form for
//     non-JSON content types and from the CSRF-Token header for JSON.
//  3. Re-read the nonce, because a successful login calls session.regenerate()
//     and the old nonce is no longer valid for writes.
//
// Success is confirmed by calling the API as the new session rather than by
// matching an error string: CTFd renders login failures as HTTP 200 with the
// form re-displayed, and the message is localized on translated instances.
func (c *Client) Login(ctx context.Context, username, password string) (*User, error) {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	return c.loginLocked(ctx, username, password)
}

// loginLocked performs the login. The caller must hold loginMu.
func (c *Client) loginLocked(ctx context.Context, username, password string) (*User, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("ctfd: username and password are both required to log in")
	}

	nonce, err := c.loginPageNonce(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"name":     {username},
		"password": {password},
		"nonce":    {nonce},
	}
	if err := c.postLoginForm(ctx, form); err != nil {
		return nil, err
	}

	// The session cookie now lives in the jar. Confirm it actually
	// authenticates before reporting success.
	me, err := c.Me(ctx)
	if err != nil {
		if IsAuth(err) || IsForbidden(err) {
			return nil, &Error{
				Kind:    KindAuth,
				Method:  http.MethodPost,
				Path:    "login",
				Message: "CTFd rejected the username or password",
			}
		}
		return nil, err
	}

	// login_user() regenerates the session, which rotates the nonce. Drop the
	// cached one so the next write re-reads it rather than being rejected.
	c.ResetCSRF()

	c.loggedIn = true
	c.log.Info("logged in", "user", me.Name, "user_id", me.ID)
	return me, nil
}

// loginPageNonce fetches GET /login, seeding the session cookie and returning
// the embedded CSRF nonce.
func (c *Client) loginPageNonce(ctx context.Context) (string, error) {
	u, err := c.ResolveSitePath("login")
	if err != nil {
		return "", err
	}

	body, _, err := c.fetchHTML(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	for _, re := range csrfPatterns {
		if m := re.FindSubmatch(body); len(m) == 2 {
			return string(m[1]), nil
		}
	}
	return "", &Error{
		Kind:    KindDecode,
		Method:  http.MethodGet,
		Path:    "login",
		Message: "could not find a CSRF nonce on the CTFd login page; the URL may not point at a CTFd instance, or a proxy may be serving a different page",
	}
}

// postLoginForm submits the login form and classifies the outcome.
func (c *Client) postLoginForm(ctx context.Context, form url.Values) error {
	u, err := c.ResolveSitePath("login")
	if err != nil {
		return err
	}

	body, resp, err := c.fetchHTML(ctx, http.MethodPost, u, form)
	if err != nil {
		return err
	}

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// A redirect means CTFd accepted the credentials and is sending the
		// browser on to the challenge listing.
		return nil

	case resp.StatusCode == http.StatusTooManyRequests:
		return &Error{
			Kind: KindRateLimited, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: "login",
			Message: "too many login attempts; CTFd limits logins to 10 per 5 seconds per address",
		}

	case resp.StatusCode == http.StatusForbidden:
		// The nonce was rejected. This is the one failure worth naming
		// precisely, because it looks like a credential problem but is not.
		return &Error{
			Kind: KindAuth, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: "login",
			Message: "CTFd rejected the login CSRF nonce; the session cookie and the nonce did not match",
		}

	case resp.StatusCode == http.StatusOK:
		// CTFd re-renders the login form on failure, with HTTP 200. Treat this
		// as a probable rejection, but let the caller's follow-up API call be
		// the authority in case a theme redirects differently.
		if hint := loginErrorHint(body); hint != "" {
			return &Error{
				Kind: KindAuth, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: "login",
				Message: hint,
			}
		}
		return nil

	default:
		return &Error{
			Kind: kindForStatus(resp.StatusCode), StatusCode: resp.StatusCode,
			Method: http.MethodPost, Path: "login",
			Message: "unexpected response from the CTFd login form",
		}
	}
}

// loginErrorHint extracts a recognizable cause from a re-rendered login page.
// It matches on stable substrings only, and returns "" when nothing is
// recognized so that a localized instance falls through to the API check
// rather than producing a wrong diagnosis.
func loginErrorHint(body []byte) string {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "username or password is incorrect"):
		return "CTFd rejected the username or password"
	case strings.Contains(s, "3rd party authentication provider"),
		strings.Contains(s, "third party authentication"):
		return "this account was registered through an OAuth provider and has no password; use an API token instead (CTFD_TOKEN)"
	case strings.Contains(s, "confirm your email"), strings.Contains(s, "email confirmation"):
		return "this account's email address is not confirmed, which CTFd requires before playing"
	default:
		return ""
	}
}

// fetchHTML performs a non-API request that returns HTML, such as the login
// form or a team page. form, when non-nil, is submitted as
// application/x-www-form-urlencoded.
//
// It deliberately does not go through do(): those requests carry the JSON
// Content-Type and expect the API envelope, neither of which applies here.
func (c *Client) fetchHTML(ctx context.Context, method string, u *url.URL, form url.Values) ([]byte, *http.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	var bodyReader io.Reader
	encoded := ""
	if form != nil {
		encoded = form.Encode()
		bodyReader = strings.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, u.String(), bodyReader)
	if err != nil {
		return nil, nil, &Error{Kind: KindTransport, Method: method, Path: u.Path, Err: err}
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = int64(len(encoded))
	}
	// A session cookie set explicitly by configuration is not in the jar, so
	// attach it here too.
	if c.opts.Session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: c.opts.Session})
	}

	if err := c.limit.Wait(reqCtx); err != nil {
		return nil, nil, c.ctxError(request{method: method, path: u.Path}, err)
	}

	resp, err := c.htmlClient().Do(req)
	if err != nil {
		return nil, nil, c.transportError(request{method: method, path: u.Path}, err)
	}
	defer drainAndClose(resp.Body)

	// The nonce sits in the page shell; a themed CTFd page can be large, so
	// cap the read rather than buffering an entire rendered challenge board.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, c.transportError(request{method: method, path: u.Path}, err)
	}
	return body, resp, nil
}

// htmlClient returns a client that never follows redirects, sharing the
// transport and cookie jar of the main client.
//
// Not following matters for login: the 302 to /challenges is the success
// signal, and following it would fetch a large HTML page only to discard it.
func (c *Client) htmlClient() *http.Client {
	return &http.Client{
		Transport:     c.http.Transport,
		Jar:           c.http.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
