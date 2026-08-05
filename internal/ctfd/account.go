package ctfd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token is an API access token belonging to the current user.
//
// Value is populated only by CreateToken: CTFd stores tokens hashed and shows
// the plaintext exactly once, at creation.
type Token struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	UserID      int    `json:"user_id,omitempty"`
	Created     string `json:"created"`
	Expiration  string `json:"expiration"`
	Description string `json:"description"`
	Value       string `json:"value,omitempty"`
}

// Expired reports whether the token's expiration is in the past.
func (t Token) Expired(now time.Time) bool {
	exp, err := parseCTFdTime(t.Expiration)
	if err != nil {
		return false
	}
	return exp.Before(now)
}

// parseCTFdTime handles the two timestamp shapes CTFd emits: RFC 3339 and a
// bare naive datetime.
func parseCTFdTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}

// Tokens lists the current user's API tokens. Values are never included.
func (c *Client) Tokens(ctx context.Context) ([]Token, error) {
	var out []Token
	if _, err := c.get(ctx, "tokens", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateToken mints a new API token.
//
// expiration, when non-empty, must be exactly YYYY-MM-DD. CTFd parses it with
// strptime and lets a ValueError escape as an HTTP 500, so the format is
// validated here rather than being discovered as a server error.
func (c *Client) CreateToken(ctx context.Context, description, expiration string) (*Token, error) {
	body := map[string]any{}
	if description != "" {
		body["description"] = description
	}
	if expiration != "" {
		if _, err := time.Parse("2006-01-02", expiration); err != nil {
			return nil, fmt.Errorf("ctfd: expiration must be formatted as YYYY-MM-DD, got %q", expiration)
		}
		body["expiration"] = expiration
	}

	var out Token
	if _, err := c.do(ctx, request{
		method:     http.MethodPost,
		path:       "tokens",
		body:       body,
		idempotent: false,
	}, &out); err != nil {
		return nil, err
	}
	// The plaintext value is returned exactly once. Register it for redaction
	// so it cannot leak through a later log line or error message.
	c.red.Add(out.Value)
	c.InvalidateCache()
	return &out, nil
}

// RevokeToken deletes an API token.
func (c *Client) RevokeToken(ctx context.Context, id int) error {
	_, err := c.do(ctx, request{
		method:     http.MethodDelete,
		path:       "tokens/" + strconv.Itoa(id),
		idempotent: true,
	}, nil)
	if err == nil {
		c.InvalidateCache()
	}
	return err
}

// ProfileUpdate holds the fields a user may change on their own account.
// Empty fields are omitted, so a caller can update one field without
// clearing the rest.
type ProfileUpdate struct {
	Name        string
	Email       string
	Website     string
	Affiliation string
	Country     string
	// Password sets a new password. CTFd requires Confirm to hold the current
	// password whenever password or email changes.
	Password string
	Confirm  string
}

func (p ProfileUpdate) body() map[string]any {
	b := map[string]any{}
	set := func(k, v string) {
		if v != "" {
			b[k] = v
		}
	}
	set("name", p.Name)
	set("email", p.Email)
	set("website", p.Website)
	set("affiliation", p.Affiliation)
	set("country", p.Country)
	set("password", p.Password)
	set("confirm", p.Confirm)
	return b
}

// UpdateProfile changes the current user's own profile.
func (c *Client) UpdateProfile(ctx context.Context, p ProfileUpdate) (*User, error) {
	body := p.body()
	if len(body) == 0 {
		return nil, fmt.Errorf("ctfd: no profile fields were provided")
	}
	// CTFd re-verifies the current password before allowing a change to the
	// credentials themselves.
	if (p.Password != "" || p.Email != "") && p.Confirm == "" {
		return nil, fmt.Errorf("ctfd: changing the password or email requires the current password in 'confirm'")
	}

	var out User
	if _, err := c.do(ctx, request{
		method:     http.MethodPatch,
		path:       "users/me",
		body:       body,
		idempotent: true,
	}, &out); err != nil {
		return nil, err
	}
	c.InvalidateCache()
	return &out, nil
}

// TeamMembers lists the current team's members.
func (c *Client) TeamMembers(ctx context.Context) ([]User, error) {
	var out []User
	if _, err := c.get(ctx, "teams/me/members", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// JoinTeam joins an existing team using its name and join password.
//
// This is an HTML form view rather than an API endpoint, so it is submitted
// form-encoded with a CSRF nonce in the body. CTFd rate limits it to 10
// attempts per 5 seconds.
func (c *Client) JoinTeam(ctx context.Context, name, password string) (*Team, error) {
	if name == "" || password == "" {
		return nil, fmt.Errorf("ctfd: both the team name and its join password are required")
	}
	if err := c.submitTeamForm(ctx, "teams/join", name, password); err != nil {
		return nil, err
	}
	return c.MyTeam(ctx)
}

// CreateTeam creates a new team with the given name and join password.
func (c *Client) CreateTeam(ctx context.Context, name, password string) (*Team, error) {
	if name == "" || password == "" {
		return nil, fmt.Errorf("ctfd: both a team name and a join password are required")
	}
	if err := c.submitTeamForm(ctx, "teams/new", name, password); err != nil {
		return nil, err
	}
	return c.MyTeam(ctx)
}

// submitTeamForm posts one of CTFd's team HTML forms.
func (c *Client) submitTeamForm(ctx context.Context, sitePath, name, password string) error {
	if c.opts.Token != "" && c.opts.Session == "" && c.opts.Username == "" {
		// The form views authenticate by session cookie. A token-only client
		// has no cookie unless CTFd issued one during token auth, which it
		// does, but relying on that silently would be fragile.
		c.log.Debug("submitting a team form using the session cookie CTFd issued during token auth")
	}

	u, err := c.ResolveSitePath(sitePath)
	if err != nil {
		return err
	}

	// The nonce for a form post comes from the page itself, and CTFd compares
	// it against the session rather than against a header.
	body, _, err := c.fetchHTML(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	nonce := ""
	for _, re := range csrfPatterns {
		if m := re.FindSubmatch(body); len(m) == 2 {
			nonce = string(m[1])
			break
		}
	}
	if nonce == "" {
		return &Error{
			Kind: KindAuth, Method: http.MethodGet, Path: sitePath,
			Message: "could not read a CSRF nonce from the team page; the account may not be logged in, or the event may not be in team mode",
		}
	}

	form := url.Values{"name": {name}, "password": {password}, "nonce": {nonce}}
	respBody, resp, err := c.fetchHTML(ctx, http.MethodPost, u, form)
	if err != nil {
		return err
	}

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Redirect means CTFd accepted it and is sending the user onward.
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return &Error{
			Kind: KindRateLimited, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: sitePath,
			Message: "CTFd rate limited the request; team joins are capped at 10 attempts per 5 seconds",
		}
	case resp.StatusCode == http.StatusForbidden:
		return &Error{
			Kind: KindForbidden, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: sitePath,
			Message: teamFormError(respBody, "the request was refused; team creation may be disabled, or the event may not be in team mode"),
		}
	case resp.StatusCode == http.StatusOK:
		// CTFd re-renders the form with errors rather than redirecting.
		return &Error{
			Kind: KindValidation, StatusCode: resp.StatusCode, Method: http.MethodPost, Path: sitePath,
			Message: teamFormError(respBody, "CTFd rejected the submission and re-displayed the form"),
		}
	default:
		return &Error{
			Kind: kindForStatus(resp.StatusCode), StatusCode: resp.StatusCode,
			Method: http.MethodPost, Path: sitePath,
			Message: "unexpected response from the CTFd team form",
		}
	}
}

// teamFormError picks a recognizable cause out of a re-rendered team form,
// falling back to a generic description on a localized instance.
func teamFormError(body []byte, fallback string) string {
	s := strings.ToLower(string(body))
	switch {
	case strings.Contains(s, "already in a team"):
		return "this account is already in a team and cannot join or create another"
	case strings.Contains(s, "that name is taken"), strings.Contains(s, "name is already"):
		return "that team name is already taken"
	case strings.Contains(s, "your password is incorrect"), strings.Contains(s, "password is incorrect"):
		return "the team join password is incorrect"
	case strings.Contains(s, "team creation is currently disabled"):
		return "team creation is disabled on this instance; join an existing team instead"
	case strings.Contains(s, "maximum number of teams"):
		return "the event has reached its maximum number of teams; join an existing team instead"
	case strings.Contains(s, "team is full"), strings.Contains(s, "maximum number of members"):
		return "that team is already at its member limit"
	default:
		return fallback
	}
}
