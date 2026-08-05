// Command ctfd-mcp is a Model Context Protocol server that exposes a CTFd
// instance to an MCP client over stdio.
//
// It is scoped to what a competitor can do: reading challenges, hints,
// scoreboards, and solve history, and — only when explicitly enabled —
// submitting flags, unlocking hints, and downloading attachments.
//
// Configuration comes from environment variables and flags; see -help.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/config"
	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
	"github.com/tjobe4340/ctfd-mcp/internal/mcpserver"
	"github.com/tjobe4340/ctfd-mcp/internal/redact"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, config.ErrHelp) {
			os.Exit(0)
		}
		// stderr only: stdout carries the JSON-RPC stream and must never
		// contain anything else.
		fmt.Fprintf(os.Stderr, "ctfd-mcp: %s\n", redact.String(err.Error()))
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Load(args, os.Stderr)
	if err != nil {
		return err
	}

	red := redact.New(cfg.Token, cfg.Session)
	logger := newLogger(cfg, red)

	logger.Info("starting", "version", config.Version, "config", slog.Any("values", cfg.Redacted()))
	warnOnRiskyConfig(cfg, logger)

	client, err := ctfd.NewClient(ctfd.Options{
		BaseURL:          cfg.BaseURL,
		Token:            cfg.Token,
		Session:          cfg.Session,
		Username:         cfg.Username,
		Password:         cfg.Password,
		UserAgent:        cfg.UserAgent,
		Timeout:          cfg.Timeout,
		MaxRetries:       cfg.MaxRetries,
		RateLimit:        cfg.RateLimit,
		RateBurst:        cfg.RateBurst,
		SubmitRate:       cfg.SubmitRateLimit,
		SubmitBurst:      cfg.SubmitRateBurst,
		PerPage:          cfg.PerPage,
		MaxPages:         cfg.MaxPages,
		MaxResponseBytes: cfg.MaxResponseBytes,
		CacheTTL:         cfg.CacheTTL,
		InsecureTLS:      cfg.InsecureTLS,
		Logger:           logger.With("component", "ctfd"),
		Redactor:         red,
	})
	if err != nil {
		return err
	}

	// Terminate cleanly on interrupt so an MCP client that kills the process
	// does not leave a half-written JSON-RPC frame on stdout.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := mcpserver.New(mcpserver.Deps{
		Client:        client,
		Config:        cfg,
		Logger:        logger.With("component", "mcp"),
		Redactor:      red,
		AllowSubmit:   cfg.AllowSubmit,
		AllowUnlock:   cfg.AllowUnlock,
		AllowDownload: cfg.AllowDownload,
	})

	// A preflight probe turns "every tool call fails mysteriously" into one
	// clear startup log line. It is deliberately non-fatal: an MCP client may
	// start this server before the CTF opens or before the VPN is up.
	srv.Preflight(ctx)

	logger.Info("serving on stdio", "tools", srv.ToolCount())
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Info("shutting down")
			return nil
		}
		return fmt.Errorf("mcp server: %w", err)
	}
	logger.Info("client disconnected")
	return nil
}

// newLogger builds a structured logger writing to stderr. Writing to stdout
// would corrupt the JSON-RPC stream, which is the single most common way to
// break an MCP stdio server.
func newLogger(cfg *config.Config, red *redact.Redactor) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(&redactingHandler{Handler: h, red: red})
}

// redactingHandler scrubs credentials from every attribute value before the
// record is written, so no call site can leak a token by accident.
type redactingHandler struct {
	slog.Handler
	red *redact.Redactor
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, h.red.String(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.scrub(a))
		return true
	})
	return h.Handler.Handle(ctx, clean)
}

func (h *redactingHandler) scrub(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.red.String(a.Value.String()))
	case slog.KindGroup:
		attrs := a.Value.Group()
		out := make([]any, 0, len(attrs))
		for _, sub := range attrs {
			out = append(out, h.scrub(sub))
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		return slog.String(a.Key, h.red.String(fmt.Sprint(a.Value.Any())))
	default:
		return a
	}
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.scrub(a)
	}
	return &redactingHandler{Handler: h.Handler.WithAttrs(scrubbed), red: h.red}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{Handler: h.Handler.WithGroup(name), red: h.red}
}

// warnOnRiskyConfig surfaces settings that weaken safety, so they appear in
// the client's log rather than being discovered after a mistake.
func warnOnRiskyConfig(cfg *config.Config, logger *slog.Logger) {
	if cfg.InsecureTLS {
		logger.Warn("TLS certificate verification is disabled; traffic to CTFd can be intercepted")
	}
	if cfg.AllowSubmit {
		logger.Warn("flag submission is enabled; submissions are irreversible, consume per-challenge attempts, and are visible to organizers")
	}
	if cfg.AllowUnlock {
		logger.Warn("hint unlocking is enabled; unlocking permanently spends points")
	}
	if cfg.AllowDownload {
		logger.Warn("attachment download is enabled", "sandbox", cfg.DownloadDir)
	}
	if cfg.TokenLooksUnusual() {
		logger.Warn(`the API token does not start with "ctfd_"; CTFd 3.x tokens normally do. If authentication fails, re-copy it from Settings > Access Tokens`)
	}
	if cfg.BaseURL.Scheme == "http" {
		logger.Warn("CTFd URL uses plain HTTP; the API token will be sent unencrypted", "url", cfg.BaseURL.String())
	}
}
