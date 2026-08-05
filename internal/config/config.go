// Package config loads and validates ctfd-mcp server configuration from
// environment variables and command-line flags.
//
// Precedence, highest first: command-line flag, environment variable, default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults for every tunable. Chosen to be safe against a live scoreboard:
// conservative rates, bounded pagination, and every point-spending or
// attempt-consuming operation disabled until explicitly enabled.
const (
	DefaultTimeout          = 30 * time.Second
	DefaultMaxRetries       = 3
	DefaultRateLimit        = 5.0
	DefaultRateBurst        = 10
	DefaultSubmitRateLimit  = 0.5
	DefaultSubmitRateBurst  = 2
	DefaultPerPage          = 50
	DefaultMaxPages         = 20
	DefaultCacheTTL         = 15 * time.Second
	DefaultMaxDownloadBytes = 64 << 20 // 64 MiB
	DefaultMaxResponseBytes = 32 << 20 // 32 MiB
)

// Version is the server version, overridable at link time with
// -ldflags "-X github.com/tjobe4340/ctfd-mcp/internal/config.Version=x.y.z".
var Version = "1.0.0"

// DefaultUserAgent identifies this client to CTFd. Event organizers watch
// request logs, and an honest User-Agent distinguishes an assisted competitor
// from a scraper.
var DefaultUserAgent = "ctfd-mcp/" + Version + " (+https://github.com/tjobe4340/ctfd-mcp)"

// Config is the fully-resolved, validated server configuration.
type Config struct {
	// BaseURL is the CTFd root, e.g. https://demo.ctfd.io. A CTFd deployed
	// under a subdirectory (APPLICATION_ROOT) is supported: include the
	// prefix, e.g. https://example.com/ctf.
	BaseURL *url.URL

	// Token is a CTFd API token ("ctfd_..."). Preferred over Session.
	Token string
	// Session is the value of the CTFd session cookie, used when no API
	// token is available. Session auth additionally requires CSRF nonces for
	// unsafe methods, which the client fetches lazily.
	Session string

	// Username and Password log in through CTFd's login form, which is what a
	// competitor without an API token has. The server exchanges them for a
	// session at startup.
	Username string
	Password string

	// AllowSubmit gates flag submission. Submissions are irreversible, count
	// against per-challenge attempt limits, and are visible to organizers.
	AllowSubmit bool
	// AllowUnlock gates hint unlocking, which permanently spends points.
	AllowUnlock bool
	// AllowDownload gates writing challenge attachments to disk.
	AllowDownload bool

	// DownloadDir is the sandbox root for attachment downloads. Every write
	// is confined to this directory.
	DownloadDir string
	// MaxDownloadBytes caps a single downloaded attachment.
	MaxDownloadBytes int64
	// MaxResponseBytes caps a single decoded API response body.
	MaxResponseBytes int64

	// Timeout bounds a single HTTP request, including retries of that request.
	Timeout time.Duration
	// MaxRetries is the number of retries (not total attempts) for
	// retry-eligible requests.
	MaxRetries int

	// RateLimit and RateBurst configure the client-side token bucket applied
	// to all API requests, in requests per second.
	RateLimit float64
	RateBurst int
	// SubmitRateLimit and SubmitRateBurst configure a second, stricter bucket
	// applied only to flag submissions, which CTFd rate-limits server-side.
	SubmitRateLimit float64
	SubmitRateBurst int

	// PerPage is the page size requested from paginated endpoints. CTFd caps
	// the effective value server-side.
	PerPage int
	// MaxPages bounds automatic pagination so a large event cannot exhaust
	// the model's context or the server's memory.
	MaxPages int

	// CacheTTL is how long read-only list responses are reused. Zero disables
	// caching.
	CacheTTL time.Duration

	// InsecureTLS disables certificate verification. Self-hosted CTFs
	// frequently use self-signed certificates; this is opt-in and warned about
	// at startup.
	InsecureTLS bool

	// UserAgent is sent on every request.
	UserAgent string

	// LogLevel is one of debug, info, warn, error.
	LogLevel string

	// tokenPrefixUnexpected records that the token did not look like a CTFd
	// 3.x token, so startup can log a hint without failing.
	tokenPrefixUnexpected bool
}

// ErrHelp is returned when the user asked for usage output.
var ErrHelp = flag.ErrHelp

// Load resolves configuration from args (excluding the program name) and the
// process environment. stderr receives usage output.
func Load(args []string, stderr io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("ctfd-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "ctfd-mcp %s - MCP server for CTFd\n\n", Version)
		fmt.Fprintf(stderr, "Usage:\n  ctfd-mcp [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nEnvironment variables (flags take precedence):\n%s\n", envHelp)
	}

	var (
		showVersion = fs.Bool("version", false, "print version and exit")

		baseURL  = fs.String("url", "", "CTFd base URL (env CTFD_URL)")
		token    = fs.String("token", "", "CTFd API token (env CTFD_TOKEN)")
		session  = fs.String("session", "", "CTFd session cookie value (env CTFD_SESSION)")
		username = fs.String("username", "", "CTFd username or email for password login (env CTFD_USERNAME)")
		password = fs.String("password", "", "CTFd password (env CTFD_PASSWORD)")

		allowSubmit   = fs.Bool("allow-submit", false, "permit flag submission (env CTFD_ALLOW_SUBMIT)")
		allowUnlock   = fs.Bool("allow-unlock", false, "permit spending points to unlock hints (env CTFD_ALLOW_UNLOCK)")
		allowDownload = fs.Bool("allow-download", false, "permit writing attachments to disk (env CTFD_ALLOW_DOWNLOAD)")

		downloadDir = fs.String("download-dir", "", "sandbox directory for attachments (env CTFD_DOWNLOAD_DIR)")
		maxDownload = fs.Int64("max-download-bytes", 0, "max bytes per attachment (env CTFD_MAX_DOWNLOAD_BYTES)")
		maxResponse = fs.Int64("max-response-bytes", 0, "max bytes per API response (env CTFD_MAX_RESPONSE_BYTES)")

		timeout    = fs.Duration("timeout", 0, "per-request timeout (env CTFD_TIMEOUT)")
		maxRetries = fs.Int("max-retries", -1, "retries for transient failures (env CTFD_MAX_RETRIES)")

		rateLimit       = fs.Float64("rate-limit", 0, "client-side requests/second (env CTFD_RATE_LIMIT)")
		rateBurst       = fs.Int("rate-burst", 0, "client-side burst (env CTFD_RATE_BURST)")
		submitRateLimit = fs.Float64("submit-rate-limit", 0, "flag submissions/second (env CTFD_SUBMIT_RATE_LIMIT)")
		submitRateBurst = fs.Int("submit-rate-burst", 0, "flag submission burst (env CTFD_SUBMIT_RATE_BURST)")

		perPage  = fs.Int("per-page", 0, "page size for list endpoints (env CTFD_PER_PAGE)")
		maxPages = fs.Int("max-pages", 0, "max pages fetched automatically (env CTFD_MAX_PAGES)")
		cacheTTL = fs.Duration("cache-ttl", -1, "read cache TTL, 0 disables (env CTFD_CACHE_TTL)")

		insecure  = fs.Bool("insecure", false, "skip TLS certificate verification (env CTFD_INSECURE_TLS)")
		userAgent = fs.String("user-agent", "", "User-Agent header (env CTFD_USER_AGENT)")
		logLevel  = fs.String("log-level", "", "debug|info|warn|error (env CTFD_LOG_LEVEL)")
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *showVersion {
		fmt.Fprintf(stderr, "ctfd-mcp %s\n", Version)
		return nil, ErrHelp
	}
	if rest := fs.Args(); len(rest) > 0 {
		return nil, fmt.Errorf("unexpected positional argument %q", rest[0])
	}

	set := flagsSet(fs)
	c := &Config{
		Token:            pickString(set, "token", *token, "CTFD_TOKEN", ""),
		Session:          pickString(set, "session", *session, "CTFD_SESSION", ""),
		Username:         pickString(set, "username", *username, "CTFD_USERNAME", ""),
		Password:         pickString(set, "password", *password, "CTFD_PASSWORD", ""),
		DownloadDir:      pickString(set, "download-dir", *downloadDir, "CTFD_DOWNLOAD_DIR", ""),
		UserAgent:        pickString(set, "user-agent", *userAgent, "CTFD_USER_AGENT", DefaultUserAgent),
		LogLevel:         strings.ToLower(pickString(set, "log-level", *logLevel, "CTFD_LOG_LEVEL", "info")),
		MaxDownloadBytes: pickInt64(set, "max-download-bytes", *maxDownload, "CTFD_MAX_DOWNLOAD_BYTES", DefaultMaxDownloadBytes),
		MaxResponseBytes: pickInt64(set, "max-response-bytes", *maxResponse, "CTFD_MAX_RESPONSE_BYTES", DefaultMaxResponseBytes),
		MaxRetries:       pickInt(set, "max-retries", *maxRetries, "CTFD_MAX_RETRIES", DefaultMaxRetries),
		RateBurst:        pickInt(set, "rate-burst", *rateBurst, "CTFD_RATE_BURST", DefaultRateBurst),
		SubmitRateBurst:  pickInt(set, "submit-rate-burst", *submitRateBurst, "CTFD_SUBMIT_RATE_BURST", DefaultSubmitRateBurst),
		PerPage:          pickInt(set, "per-page", *perPage, "CTFD_PER_PAGE", DefaultPerPage),
		MaxPages:         pickInt(set, "max-pages", *maxPages, "CTFD_MAX_PAGES", DefaultMaxPages),
		RateLimit:        pickFloat(set, "rate-limit", *rateLimit, "CTFD_RATE_LIMIT", DefaultRateLimit),
		SubmitRateLimit:  pickFloat(set, "submit-rate-limit", *submitRateLimit, "CTFD_SUBMIT_RATE_LIMIT", DefaultSubmitRateLimit),
		Timeout:          pickDuration(set, "timeout", *timeout, "CTFD_TIMEOUT", DefaultTimeout),
		CacheTTL:         pickDuration(set, "cache-ttl", *cacheTTL, "CTFD_CACHE_TTL", DefaultCacheTTL),
		AllowSubmit:      pickBool(set, "allow-submit", *allowSubmit, "CTFD_ALLOW_SUBMIT", false),
		AllowUnlock:      pickBool(set, "allow-unlock", *allowUnlock, "CTFD_ALLOW_UNLOCK", false),
		AllowDownload:    pickBool(set, "allow-download", *allowDownload, "CTFD_ALLOW_DOWNLOAD", false),
		InsecureTLS:      pickBool(set, "insecure", *insecure, "CTFD_INSECURE_TLS", false),
	}

	raw := pickString(set, "url", *baseURL, "CTFD_URL", "")
	u, err := ParseBaseURL(raw)
	if err != nil {
		return nil, err
	}
	c.BaseURL = u

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseBaseURL normalizes a CTFd root URL. A bare host is upgraded to https,
// and the path is normalized to a trailing-slash form so that subdirectory
// deployments (CTFd's APPLICATION_ROOT) resolve correctly under url.Parse.
func ParseBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("CTFd base URL is required: set CTFD_URL or pass -url (e.g. https://demo.ctfd.io)")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid CTFd URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid CTFd URL scheme %q: want http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid CTFd URL %q: missing host", raw)
	}
	// Query and fragment are meaningless on a base URL and would otherwise be
	// silently inherited by every resolved request path.
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil

	// Callers resolve relative references against BaseURL. A trailing slash
	// makes "api/v1/challenges" resolve *under* an APPLICATION_ROOT prefix
	// rather than replacing the last path segment.
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

func (c *Config) validate() error {
	var errs []error

	// Exactly one authentication mode. Silently preferring one over another
	// would make a typo in the intended credential look like a server bug.
	modes := 0
	if c.Token != "" {
		modes++
	}
	if c.Session != "" {
		modes++
	}
	if c.Username != "" || c.Password != "" {
		modes++
	}
	switch {
	case modes == 0:
		errs = append(errs, errors.New("no credentials: set CTFD_USERNAME and CTFD_PASSWORD to log in, or CTFD_TOKEN to an API token (Settings > Access Tokens), or CTFD_SESSION to a session cookie value"))
	case modes > 1:
		errs = append(errs, errors.New("more than one credential is set: choose exactly one of CTFD_TOKEN, CTFD_SESSION, or CTFD_USERNAME plus CTFD_PASSWORD"))
	}
	if c.Username != "" && c.Password == "" {
		errs = append(errs, errors.New("CTFD_USERNAME is set but CTFD_PASSWORD is empty"))
	}
	if c.Password != "" && c.Username == "" {
		errs = append(errs, errors.New("CTFD_PASSWORD is set but CTFD_USERNAME is empty"))
	}
	if c.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("timeout must be positive, got %s", c.Timeout))
	}
	if c.MaxRetries < 0 {
		errs = append(errs, fmt.Errorf("max-retries must be >= 0, got %d", c.MaxRetries))
	}
	if c.MaxRetries > 10 {
		errs = append(errs, fmt.Errorf("max-retries must be <= 10, got %d", c.MaxRetries))
	}
	if c.RateLimit <= 0 {
		errs = append(errs, fmt.Errorf("rate-limit must be positive, got %g", c.RateLimit))
	}
	if c.RateBurst < 1 {
		errs = append(errs, fmt.Errorf("rate-burst must be >= 1, got %d", c.RateBurst))
	}
	if c.SubmitRateLimit <= 0 {
		errs = append(errs, fmt.Errorf("submit-rate-limit must be positive, got %g", c.SubmitRateLimit))
	}
	if c.SubmitRateBurst < 1 {
		errs = append(errs, fmt.Errorf("submit-rate-burst must be >= 1, got %d", c.SubmitRateBurst))
	}
	if c.PerPage < 1 || c.PerPage > 100 {
		errs = append(errs, fmt.Errorf("per-page must be between 1 and 100, got %d", c.PerPage))
	}
	if c.MaxPages < 1 {
		errs = append(errs, fmt.Errorf("max-pages must be >= 1, got %d", c.MaxPages))
	}
	if c.CacheTTL < 0 {
		errs = append(errs, fmt.Errorf("cache-ttl must be >= 0, got %s", c.CacheTTL))
	}
	if c.MaxDownloadBytes < 1 {
		errs = append(errs, fmt.Errorf("max-download-bytes must be positive, got %d", c.MaxDownloadBytes))
	}
	if c.MaxResponseBytes < 1 {
		errs = append(errs, fmt.Errorf("max-response-bytes must be positive, got %d", c.MaxResponseBytes))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("invalid log-level %q: want debug, info, warn, or error", c.LogLevel))
	}

	if c.AllowDownload {
		if c.DownloadDir == "" {
			errs = append(errs, errors.New("download is enabled but no download directory is set: set CTFD_DOWNLOAD_DIR"))
		} else {
			abs, err := filepath.Abs(c.DownloadDir)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid download-dir %q: %w", c.DownloadDir, err))
			} else {
				c.DownloadDir = abs
			}
		}
	}

	if c.Token != "" && !strings.HasPrefix(c.Token, "ctfd_") {
		// CTFd 3.x mints tokens with a "ctfd_" prefix. Older or proxied
		// deployments may not, so this is a warning surfaced as a non-fatal
		// note rather than a hard failure.
		c.tokenPrefixUnexpected = true
	}

	return errors.Join(errs...)
}

// TokenLooksUnusual reports whether the configured token lacks the "ctfd_"
// prefix used by CTFd 3.x.
func (c *Config) TokenLooksUnusual() bool { return c.tokenPrefixUnexpected }

// Redacted returns a copy safe to log: credentials are replaced with a
// fingerprint that is stable per-credential but not reversible.
func (c *Config) Redacted() map[string]any {
	return map[string]any{
		"base_url":          c.BaseURL.String(),
		"auth":              c.authDescription(),
		"allow_submit":      c.AllowSubmit,
		"allow_unlock":      c.AllowUnlock,
		"allow_download":    c.AllowDownload,
		"download_dir":      c.DownloadDir,
		"timeout":           c.Timeout.String(),
		"max_retries":       c.MaxRetries,
		"rate_limit":        c.RateLimit,
		"submit_rate_limit": c.SubmitRateLimit,
		"per_page":          c.PerPage,
		"max_pages":         c.MaxPages,
		"cache_ttl":         c.CacheTTL.String(),
		"insecure_tls":      c.InsecureTLS,
		"log_level":         c.LogLevel,
	}
}

func (c *Config) authDescription() string {
	switch {
	case c.Token != "":
		return "api-token"
	case c.Session != "":
		return "session-cookie"
	case c.Username != "":
		return "password-login"
	default:
		return "none"
	}
}

const envHelp = `  CTFD_URL                 CTFd base URL (required)
  CTFD_USERNAME            username or email for password login
  CTFD_PASSWORD            password for CTFD_USERNAME
  CTFD_TOKEN               API token from Settings > Access Tokens
  CTFD_SESSION             session cookie value
                           (set exactly one of: username+password, token, session)
  CTFD_ALLOW_SUBMIT        "true" to permit flag submission
  CTFD_ALLOW_UNLOCK        "true" to permit spending points on hints
  CTFD_ALLOW_DOWNLOAD      "true" to permit writing attachments to disk
  CTFD_DOWNLOAD_DIR        sandbox directory for attachments
  CTFD_MAX_DOWNLOAD_BYTES  max bytes per attachment
  CTFD_MAX_RESPONSE_BYTES  max bytes per API response
  CTFD_TIMEOUT             per-request timeout, e.g. 30s
  CTFD_MAX_RETRIES         retries for transient failures
  CTFD_RATE_LIMIT          client-side requests/second
  CTFD_RATE_BURST          client-side burst
  CTFD_SUBMIT_RATE_LIMIT   flag submissions/second
  CTFD_SUBMIT_RATE_BURST   flag submission burst
  CTFD_PER_PAGE            page size for list endpoints (1-100)
  CTFD_MAX_PAGES           max pages fetched automatically
  CTFD_CACHE_TTL           read cache TTL, e.g. 15s ("0" disables)
  CTFD_INSECURE_TLS        "true" to skip TLS verification
  CTFD_USER_AGENT          User-Agent header
  CTFD_LOG_LEVEL           debug|info|warn|error`

// flagsSet reports which flags were explicitly provided, so that a flag set to
// its zero value still overrides the environment.
func flagsSet(fs *flag.FlagSet) map[string]bool {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func pickString(set map[string]bool, name, flagVal, env, def string) string {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func pickBool(set map[string]bool, name string, flagVal bool, env string, def bool) bool {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
		// Accept the common non-Go spellings rather than silently ignoring them.
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "yes", "on", "enabled":
			return true
		case "no", "off", "disabled":
			return false
		}
	}
	return def
}

func pickInt(set map[string]bool, name string, flagVal int, env string, def int) int {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func pickInt64(set map[string]bool, name string, flagVal int64, env string, def int64) int64 {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return def
}

func pickFloat(set map[string]bool, name string, flagVal float64, env string, def float64) float64 {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	return def
}

func pickDuration(set map[string]bool, name string, flagVal time.Duration, env string, def time.Duration) time.Duration {
	if set[name] {
		return flagVal
	}
	if v, ok := os.LookupEnv(env); ok {
		s := strings.TrimSpace(v)
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
		// Bare numbers are interpreted as seconds, which is what most people
		// mean when they write CTFD_TIMEOUT=60.
		if n, err := strconv.Atoi(s); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}
