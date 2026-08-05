package config

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestParseBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare host upgrades to https", "demo.ctfd.io", "https://demo.ctfd.io/", false},
		{"explicit https", "https://ctf.example.com", "https://ctf.example.com/", false},
		{"plain http is allowed", "http://localhost:8000", "http://localhost:8000/", false},
		{"subdirectory keeps its prefix", "https://example.com/ctf", "https://example.com/ctf/", false},
		{"trailing slash preserved", "https://example.com/ctf/", "https://example.com/ctf/", false},
		{"query is stripped", "https://example.com/?a=b", "https://example.com/", false},
		{"credentials are stripped", "https://user:pw@example.com", "https://example.com/", false},
		{"empty is rejected", "", "", true},
		{"unsupported scheme", "ftp://example.com", "", true},
		{"missing host", "https://", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseBaseURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBaseURL(%q): %v", tc.in, err)
			}
			if got.String() != tc.want {
				t.Errorf("ParseBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("CTFD_URL", "https://from-env.example.com")
	t.Setenv("CTFD_TOKEN", "ctfd_envtoken000000000000")
	t.Setenv("CTFD_PER_PAGE", "10")

	cfg, err := Load([]string{"-url", "https://from-flag.example.com", "-per-page", "77"}, io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.BaseURL.String(); got != "https://from-flag.example.com/" {
		t.Errorf("BaseURL = %q, want the flag value", got)
	}
	if cfg.PerPage != 77 {
		t.Errorf("PerPage = %d, want 77", cfg.PerPage)
	}
	// Unset flags still fall through to the environment.
	if cfg.Token != "ctfd_envtoken000000000000" {
		t.Errorf("Token = %q, want the environment value", cfg.Token)
	}
}

func TestExplicitFalseFlagBeatsTruthyEnvironment(t *testing.T) {
	// A flag set to its zero value must still win, which a naive
	// "if value != zero" check would get wrong.
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_TOKEN", "ctfd_token0000000000000000")
	t.Setenv("CTFD_ALLOW_SUBMIT", "true")

	cfg, err := Load([]string{"-allow-submit=false"}, io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AllowSubmit {
		t.Error("an explicit -allow-submit=false must override CTFD_ALLOW_SUBMIT=true")
	}
}

func TestBooleanEnvSpellings(t *testing.T) {
	for _, v := range []string{"true", "1", "yes", "on", "enabled", "TRUE"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("CTFD_URL", "https://x.example.com")
			t.Setenv("CTFD_TOKEN", "ctfd_token0000000000000000")
			t.Setenv("CTFD_ALLOW_SUBMIT", v)
			cfg, err := Load(nil, io.Discard)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.AllowSubmit {
				t.Errorf("CTFD_ALLOW_SUBMIT=%q should enable submission", v)
			}
		})
	}
	for _, v := range []string{"false", "0", "no", "off", "disabled", ""} {
		t.Run("off/"+v, func(t *testing.T) {
			t.Setenv("CTFD_URL", "https://x.example.com")
			t.Setenv("CTFD_TOKEN", "ctfd_token0000000000000000")
			t.Setenv("CTFD_ALLOW_SUBMIT", v)
			cfg, err := Load(nil, io.Discard)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.AllowSubmit {
				t.Errorf("CTFD_ALLOW_SUBMIT=%q should leave submission disabled", v)
			}
		})
	}
}

func TestBareNumberTimeoutIsSeconds(t *testing.T) {
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_TOKEN", "ctfd_token0000000000000000")
	t.Setenv("CTFD_TIMEOUT", "45")

	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout = %s, want 45s", cfg.Timeout)
	}
}

func TestValidationRejectsBadConfigurations(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		args    []string
		wantErr string
	}{
		{
			name:    "no credentials",
			env:     map[string]string{"CTFD_URL": "https://x.example.com"},
			wantErr: "no credentials",
		},
		{
			name: "both credentials",
			env: map[string]string{
				"CTFD_URL": "https://x.example.com", "CTFD_TOKEN": "ctfd_a000000000000000",
				"CTFD_SESSION": "sessionvalue123",
			},
			wantErr: "more than one credential is set",
		},
		{
			name:    "no URL",
			env:     map[string]string{"CTFD_TOKEN": "ctfd_a000000000000000"},
			wantErr: "base URL is required",
		},
		{
			name:    "per-page above the CTFd cap",
			env:     map[string]string{"CTFD_URL": "https://x.example.com", "CTFD_TOKEN": "ctfd_a000000000000000"},
			args:    []string{"-per-page", "500"},
			wantErr: "per-page must be between 1 and 100",
		},
		{
			name:    "download enabled without a directory",
			env:     map[string]string{"CTFD_URL": "https://x.example.com", "CTFD_TOKEN": "ctfd_a000000000000000"},
			args:    []string{"-allow-download"},
			wantErr: "no download directory",
		},
		{
			name:    "bad log level",
			env:     map[string]string{"CTFD_URL": "https://x.example.com", "CTFD_TOKEN": "ctfd_a000000000000000"},
			args:    []string{"-log-level", "chatty"},
			wantErr: "invalid log-level",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear everything the loader reads so cases stay independent.
			for _, k := range []string{"CTFD_URL", "CTFD_TOKEN", "CTFD_SESSION", "CTFD_PER_PAGE", "CTFD_ALLOW_SUBMIT", "CTFD_TIMEOUT", "CTFD_DOWNLOAD_DIR", "CTFD_LOG_LEVEL"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load(tc.args, io.Discard)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestPasswordLoginIsAValidAuthMode(t *testing.T) {
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_USERNAME", "player1")
	t.Setenv("CTFD_PASSWORD", "hunter2")

	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatalf("username and password should be accepted as credentials: %v", err)
	}
	if cfg.Username != "player1" || cfg.Password != "hunter2" {
		t.Errorf("credentials not loaded: %q / (password %d chars)", cfg.Username, len(cfg.Password))
	}
	if got := cfg.Redacted()["auth"]; got != "password-login" {
		t.Errorf("auth = %v, want password-login", got)
	}
	// The password must never appear in loggable output.
	for k, v := range cfg.Redacted() {
		if s, ok := v.(string); ok && strings.Contains(s, "hunter2") {
			t.Errorf("Redacted()[%q] leaked the password", k)
		}
	}
}

func TestIncompleteOrConflictingCredentials(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "username without password",
			env:     map[string]string{"CTFD_URL": "https://x.example.com", "CTFD_USERNAME": "player1"},
			wantErr: "CTFD_PASSWORD is empty",
		},
		{
			name:    "password without username",
			env:     map[string]string{"CTFD_URL": "https://x.example.com", "CTFD_PASSWORD": "hunter2"},
			wantErr: "CTFD_USERNAME is empty",
		},
		{
			name: "token and password login together",
			env: map[string]string{
				"CTFD_URL": "https://x.example.com", "CTFD_TOKEN": "ctfd_a000000000000000",
				"CTFD_USERNAME": "player1", "CTFD_PASSWORD": "hunter2",
			},
			wantErr: "more than one credential is set",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"CTFD_URL", "CTFD_TOKEN", "CTFD_SESSION", "CTFD_USERNAME", "CTFD_PASSWORD"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load(nil, io.Discard)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_TOKEN", "ctfd_token0000000000000000")

	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Everything irreversible must be off unless explicitly enabled.
	if cfg.AllowSubmit {
		t.Error("flag submission must default to disabled")
	}
	if cfg.AllowUnlock {
		t.Error("hint unlocking must default to disabled")
	}
	if cfg.AllowDownload {
		t.Error("attachment download must default to disabled")
	}
	if cfg.InsecureTLS {
		t.Error("TLS verification must default to enabled")
	}
	if cfg.Timeout <= 0 || cfg.MaxPages < 1 || cfg.RateLimit <= 0 {
		t.Error("numeric defaults must be usable")
	}
}

func TestRedactedNeverContainsCredentials(t *testing.T) {
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_TOKEN", "ctfd_supersecrettoken00000")

	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for k, v := range cfg.Redacted() {
		if s, ok := v.(string); ok && strings.Contains(s, "supersecret") {
			t.Errorf("Redacted()[%q] leaked the token: %q", k, s)
		}
	}
	if cfg.Redacted()["auth"] != "api-token" {
		t.Errorf("auth = %v, want api-token", cfg.Redacted()["auth"])
	}
}

func TestUnusualTokenIsFlaggedNotRejected(t *testing.T) {
	t.Setenv("CTFD_URL", "https://x.example.com")
	t.Setenv("CTFD_TOKEN", "legacy-token-without-prefix")

	cfg, err := Load(nil, io.Discard)
	if err != nil {
		t.Fatalf("a non-standard token should be accepted, not rejected: %v", err)
	}
	if !cfg.TokenLooksUnusual() {
		t.Error("a token without the ctfd_ prefix should be flagged for a warning")
	}
}
