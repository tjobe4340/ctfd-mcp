package ctfd

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// csrfTTL is how long a scraped nonce is reused. CTFd rotates the nonce per
// session rather than per request, but re-scraping periodically keeps a
// long-lived server from wedging on a stale value after a session refresh.
const csrfTTL = 10 * time.Minute

// csrfPatterns match the nonce as CTFd embeds it in the page shell. CTFd has
// used both an `init` JS object and a hidden form input across 3.x releases,
// so both are tried.
var csrfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`['"]csrfNonce['"]\s*:\s*['"]([0-9a-fA-F]{16,})['"]`),
	regexp.MustCompile(`name=['"]nonce['"]\s+value=['"]([0-9a-fA-F]{16,})['"]`),
	regexp.MustCompile(`value=['"]([0-9a-fA-F]{16,})['"]\s+name=['"]nonce['"]`),
}

// csrfToken returns a CSRF nonce for session-cookie authentication, scraping
// and caching one if needed.
//
// API-token auth does not need this; the nonce is only required because CTFd
// protects cookie-authenticated unsafe methods against cross-site requests.
func (c *Client) csrfToken(ctx context.Context) (string, error) {
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()

	if c.csrfNonce != "" && c.now().Sub(c.csrfSetAt) < csrfTTL {
		return c.csrfNonce, nil
	}

	nonce, err := c.fetchCSRFNonce(ctx)
	if err != nil {
		return "", err
	}
	c.csrfNonce, c.csrfSetAt = nonce, c.now()
	return nonce, nil
}

// fetchCSRFNonce loads an authenticated HTML page and extracts the nonce.
//
// Any authenticated page carries it. /challenges is used because it is present
// on every CTFd instance and is cheap relative to the scoreboard.
func (c *Client) fetchCSRFNonce(ctx context.Context) (string, error) {
	u, err := c.ResolveSitePath("challenges")
	if err != nil {
		return "", err
	}

	body, resp, err := c.fetchHTML(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &Error{
			Kind: KindAuth, StatusCode: resp.StatusCode, Method: http.MethodGet, Path: "challenges",
			Message: "the session was rejected while fetching a CSRF nonce; it may have expired",
		}
	}

	for _, re := range csrfPatterns {
		if m := re.FindSubmatch(body); len(m) == 2 {
			return string(m[1]), nil
		}
	}

	return "", &Error{
		Kind:       KindAuth,
		StatusCode: resp.StatusCode,
		Method:     http.MethodGet,
		Path:       "challenges",
		Message: fmt.Sprintf("could not find a CSRF nonce in the CTFd page (HTTP %d). "+
			"Cookie authentication cannot perform writes without one; "+
			"an API token (CTFD_TOKEN) needs no nonce and is more reliable", resp.StatusCode),
	}
}

// ResetCSRF clears the cached nonce, forcing a re-scrape on the next unsafe
// request. Called when a write fails in a way that suggests a stale nonce.
func (c *Client) ResetCSRF() {
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	c.csrfNonce, c.csrfSetAt = "", time.Time{}
}
