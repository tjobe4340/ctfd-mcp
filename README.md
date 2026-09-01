# ctfd-mcp

An MCP server that exposes a [CTFd](https://ctfd.io) capture-the-flag instance to an
MCP client, from a **competitor's** point of view.

It ships as a single static Go binary with no runtime dependencies. Flag submission,
hint unlocks, and attachment downloads are **enabled by default**, because installing
a competitor tool is an affirmative choice to play. They can each be disabled when a
read-only setup is preferred.

Verified against CTFd **3.6.x**, **3.7.x**, and **3.8.x** — see
[version compatibility](#ctfd-version-compatibility).

---

## Capabilities

**Read the event** — challenges with descriptions, connection info, attachments,
tags, hints and their costs; solve counts and who solved what; the scoreboard, score
history over time, and organizer announcements; any competitor's or team's public
profile and solves.

**Play** - submit flags, unlock hints, and download challenge attachments into a
sandbox directory. All three work immediately; downloads go to `ctfd-downloads`
beside the server's working directory unless you choose another location.

**Learn** — read the organizers' official solutions once they unlock, and rate
challenges with written feedback. *(CTFd 3.8+)*

**Manage your account** — log in with a password, mint and revoke API tokens, edit
your profile, view your team, join or create one.

**Know where you stand** — your own solves, failed submissions, and point awards;
the exact strings you previously submitted, where the event allows it; your rank and
the competitors immediately around you; and a per-session record of what this server
has submitted.

What it does **not** do:

- **Anything requiring an organizer account.** CTFd gates challenge authoring, user
  administration, the global submission log, config, and statistics behind
  `@admins_only`, so those endpoints would only ever return 403 for a competitor and
  are deliberately absent.
- **Register an account.** Sign up in a browser first; this server logs in as an
  existing user.
- **Leave a team.** CTFd itself provides no player-facing way to do that.

| | |
| --- | --- |
| Tools | 23 (14 read-only, 9 writing), or 11 in lite |
| Auth | API token, username + password, or session cookie |
| CTFd | 3.6.x, 3.7.x, 3.8.x |
| Runtime deps | none — one static binary |
| Enabled by default | all competitor features |

---

## Contents

- [Install](#install)
- [Authenticate](#authenticate)
- [Configure your MCP client](#configure-your-mcp-client)
- [Tools](#tools)
- [CTFd version compatibility](#ctfd-version-compatibility)
- [Configuration reference](#configuration-reference)
- [Safety model](#safety-model)
- [How it handles CTFd's rough edges](#how-it-handles-ctfds-rough-edges)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## Install

Requires Go 1.25 or newer to build.

```bash
go build -trimpath -ldflags "-s -w" -o bin/ctfd-mcp ./cmd/ctfd-mcp
```

On Windows:

```bash
go build -trimpath -ldflags "-s -w" -o bin/ctfd-mcp.exe ./cmd/ctfd-mcp
```

Cross-compiling is a matter of setting `GOOS`/`GOARCH`; there is no cgo.

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o bin/ctfd-mcp-linux ./cmd/ctfd-mcp
```

---

## Authenticate

Pick exactly one of three modes. **Use an API token** unless you have a reason not
to.

### API token — recommended

In CTFd: **Settings → Access Tokens → Generate**.

```
CTFD_TOKEN=ctfd_...
```

Two reasons this is the right default. It is more **reliable**: CTFd skips CSRF
entirely when an `Authorization` header is present, so there is no nonce to scrape,
rotate, or go stale, and no session to expire mid-event. And it is **safer to store**:
an MCP config file lives on disk in cleartext, and a token there is scoped to one
account, expires on its own, and can be revoked from the CTFd UI without changing
anything else. A password in that same file is a reusable credential you would have
to rotate manually.

Tokens are `ctfd_` plus 64 hex characters and **expire after 30 days by default**.
CTFd before 3.6 issues them without the prefix; those work too, with a warning.

### Username and password — for bootstrapping

If you don't have a token yet — or the instance has token generation disabled — use
your normal CTFd login:

```
CTFD_USERNAME=your_username     # or your email address
CTFD_PASSWORD=your_password
```

The server logs in at startup, holds the session, and manages CSRF nonces for you,
including re-fetching one when CTFd rotates it. If login fails at startup (VPN not up,
event not open yet) it retries on the first tool call rather than staying broken.

Once running, ask for a token with `ctfd_create_token`, then move to
`CTFD_TOKEN` and drop the password from your config.

### Session cookie

```
CTFD_SESSION=...
```

Copy the `session` cookie from your browser. Equivalent to password login, but with
no way to re-authenticate once it expires.

Setting more than one mode is rejected at startup rather than silently preferring
one, so a typo in the credential you meant to use doesn't look like a server bug.

---

## Configure your MCP client

### Claude Code

```bash
claude mcp add ctfd --env CTFD_URL=https://demo.ctfd.io --env CTFD_TOKEN=ctfd_your_token_here -- /absolute/path/to/ctfd-mcp
```

If you don't have a token yet, swap in `--env CTFD_USERNAME=you --env
CTFD_PASSWORD=secret`, then use `ctfd_create_token` and move to the token.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ctfd": {
      "command": "C:\\path\\to\\ctfd-mcp.exe",
      "env": {
        "CTFD_URL": "https://demo.ctfd.io",
        "CTFD_TOKEN": "ctfd_your_token_here"
      }
    }
  }
}
```

### Lite configuration with a custom download directory

```json
{
  "mcpServers": {
    "ctfd": {
      "command": "/usr/local/bin/ctfd-mcp",
      "env": {
        "CTFD_URL": "https://ctf.example.com",
        "CTFD_TOKEN": "ctfd_your_token_here",
        "CTFD_LITE": "true",
        "CTFD_DOWNLOAD_DIR": "/home/you/ctf/downloads",
        "CTFD_LOG_LEVEL": "info"
      }
    }
  }
}
```

Verify the binary works before wiring it up:

```bash
ctfd-mcp -version
```

---

## Tools

23 tools in the default profile, **11 in lite**. Read-only unless marked otherwise.
Tools marked *3.8+* use endpoints CTFd added in 3.8; against an older instance they
say so rather than failing.

### Lite profile

```
CTFD_LITE=true
```

Registers only what is needed to play — identity, challenges, flags, hints,
attachments, the scoreboard, and your own history:

`ctfd_whoami` · `ctfd_my_progress` · `ctfd_list_challenges` · `ctfd_get_challenge` ·
`ctfd_submit_flag` · `ctfd_my_submissions` · `ctfd_session_report` ·
`ctfd_get_hint` · `ctfd_unlock_hint` · `ctfd_download_files` · `ctfd_scoreboard`

Left out: the outward-looking reads (other competitors' profiles, per-challenge
solver lists, score timelines, announcements), the CTFd 3.8 extras (official
solutions, ratings), and account administration (tokens, profile, team membership).

This is worth using. Every tool definition is sent to the model on connect and
competes for its attention when it picks one, so a smaller, sharper set measurably
improves tool selection — and nothing in the list above is needed to read a
challenge, work it, and submit a flag.

### Orientation

| Tool | What it does |
| --- | --- |
| `ctfd_whoami` | Your user, team, score, and rank. Call this first — it also detects whether the event is in user or team mode. |
| `ctfd_my_progress` | Authoritative solve/fail/award history from CTFd. Hint unlocks appear as negative awards. Works even when the scoreboard is hidden. |
| `ctfd_lookup_account` | Look up another competitor or team by ID or name, optionally with their public solves. |

### Challenges

| Tool | What it does |
| --- | --- |
| `ctfd_list_challenges` | Survey the event. Filter by category, search text, or solve status; sort by category, value, solves, or name. |
| `ctfd_get_challenge` | One challenge in full: description, connection info, attachments, tags, hints with costs, attempts used and remaining. |
| `ctfd_challenge_solvers` | Who solved a challenge and when — a good proxy for real difficulty. |

### Playing

| Tool | Writes? | What it does |
| --- | --- | --- |
| `ctfd_submit_flag` | **yes** | Submit a flag. Enabled by default; supports `dry_run` and refuses duplicates and exhausted attempt budgets. |
| `ctfd_session_report` | no | What this process has submitted so far. Flags are stored hashed, never echoed. |
| `ctfd_get_hint` | no | Read a hint. Free and already-unlocked hints return their content directly. |
| `ctfd_unlock_hint` | **yes** | Unlock a hint. Enabled by default; paid hints spend their listed points immediately when called. |
| `ctfd_download_files` | **yes** | Save challenge attachments into a sandbox directory. Enabled by default, saving to `ctfd-downloads` unless configured otherwise. |
| `ctfd_get_solution` | **yes** | *3.8+* — read the organizers' official writeup. Most unlock only after you solve the challenge. Free, but CTFd records that you viewed it, so revealing needs `unlock: true`. |
| `ctfd_rate_challenge` | **yes** | *3.8+* — thumbs up or down plus optional written feedback. CTFd requires you to have solved it first. |
| `ctfd_my_submissions` | no | Everything you have previously submitted, newest first. Where the event allows it, this includes **the exact strings you typed**; otherwise it falls back to your solve and failure history so you can still see what was attempted. |

### Situational awareness

| Tool | What it does |
| --- | --- |
| `ctfd_scoreboard` | Standings. `around_me: true` shows your immediate competition rather than the leaders. |
| `ctfd_score_history` | Scoring timelines for the top accounts — what the leaders solved, in what order. |
| `ctfd_notifications` | Organizer announcements, newest first. |

### Account management

| Tool | Writes? | What it does |
| --- | --- | --- |
| `ctfd_list_tokens` | no | Your API tokens, with expiry status. Values are never shown — CTFd stores them hashed. |
| `ctfd_create_token` | **yes** | Mint an API token. Returns the plaintext once. Needs `confirm: true`. |
| `ctfd_revoke_token` | **yes** | Delete a token. Needs `confirm: true`. |
| `ctfd_update_profile` | **yes** | Change name, website, affiliation, country, email, or password. Only the fields you pass are touched. |
| `ctfd_my_team` | no | Your team and its members. Says so plainly in user mode or when you have no team. |
| `ctfd_join_or_create_team` | **yes** | Join a team by name and join password, or create one. Needs `confirm: true`. |

---

## CTFd version compatibility

Everything works on **3.6.x, 3.7.x, and 3.8.x**. The three versions differ in ways
that would silently corrupt output if a client assumed the newest shapes, so each
difference is handled and pinned by a test.

| | 3.6.x | 3.7.x | 3.8.x |
| --- | --- | --- | --- |
| Core reads, flag submission, hints, unlocks | yes | yes | yes |
| Tokens, profile, teams | yes | yes | yes |
| Locked hint carries a `title` | no | yes | yes |
| Challenge `attribution` (author) | no | yes | yes |
| Scoreboard brackets/divisions | no | yes | yes |
| `ctfd_get_solution`, `ctfd_rate_challenge` | no | no | yes |
| `ctfd_my_submissions` | solve/fail history fallback | solve/fail history fallback | full history when enabled; otherwise fallback |

Where a field is absent it stays absent rather than rendering as `null`, an empty
label, or a placeholder. Where an endpoint does not exist the tool explains the
version requirement instead of surfacing a bare 404. `ctfd_my_submissions` remains
useful on 3.6 and 3.7 by reconstructing your solve and failure history; only the
raw submitted strings require the 3.8 endpoint and organizer permission.

Two details worth knowing:

- **Authentication and CSRF are byte-identical across 3.6.1–3.8.x.** The
  `Content-Type` gate, the `Authorization` CSRF bypass, the `CSRF-Token` header for
  JSON writes, and the `nonce` form field for form posts all behave the same.
- **CTFd before 3.6.0 issues API tokens without the `ctfd_` prefix.** Those are
  accepted with a warning rather than rejected, so a 3.5 instance may work — but it
  is not tested and not claimed.

---

## Configuration reference

Every setting has a flag and an environment variable. Flags win.

### Required

| Variable | Flag | Description |
| --- | --- | --- |
| `CTFD_URL` | `-url` | CTFd base URL. A bare host is upgraded to `https`. Subdirectory installs (`https://example.com/ctf`) are supported. |

Plus exactly one credential set:

| Variable | Flag | Description |
| --- | --- | --- |
| `CTFD_TOKEN` | `-token` | API token from Settings → Access Tokens. **Recommended.** |
| `CTFD_USERNAME` + `CTFD_PASSWORD` | `-username`, `-password` | Normal CTFd login. The server holds the session and manages CSRF nonces. |
| `CTFD_SESSION` | `-session` | Session cookie value copied from a browser. |

### Capability controls - all default to `true`

| Variable | Flag | Description |
| --- | --- | --- |
| `CTFD_ALLOW_SUBMIT` | `-allow-submit` | Set to `false` to disable flag submission. |
| `CTFD_ALLOW_UNLOCK` | `-allow-unlock` | Set to `false` to disable spending points to unlock hints. |
| `CTFD_ALLOW_DOWNLOAD` | `-allow-download` | Set to `false` to disable writing attachments to disk. |

### Profile

| Variable | Flag | Default | Description |
| --- | --- | --- | --- |
| `CTFD_LITE` | `-lite` | `false` | Register only the 11 core play tools. See [Lite profile](#lite-profile). |

### Everything else

| Variable | Flag | Default | Description |
| --- | --- | --- | --- |
| `CTFD_DOWNLOAD_DIR` | `-download-dir` | `ctfd-downloads` | Sandbox directory for attachments. All writes are confined to it. Relative paths resolve from the server's working directory. |
| `CTFD_MAX_DOWNLOAD_BYTES` | `-max-download-bytes` | 64 MiB | Per-attachment size cap. |
| `CTFD_MAX_RESPONSE_BYTES` | `-max-response-bytes` | 32 MiB | Per-response size cap. |
| `CTFD_TIMEOUT` | `-timeout` | `30s` | Per-request timeout. A bare number means seconds. |
| `CTFD_MAX_RETRIES` | `-max-retries` | `3` | Retries for transient failures. Never applies to flag submission. |
| `CTFD_RATE_LIMIT` | `-rate-limit` | `5` | Client-side requests per second. |
| `CTFD_RATE_BURST` | `-rate-burst` | `10` | Client-side burst allowance. |
| `CTFD_SUBMIT_RATE_LIMIT` | `-submit-rate-limit` | `0.5` | Flag submissions per second. |
| `CTFD_SUBMIT_RATE_BURST` | `-submit-rate-burst` | `2` | Submission burst allowance. |
| `CTFD_PER_PAGE` | `-per-page` | `50` | Page size for paginated endpoints. CTFd caps this at 100. |
| `CTFD_MAX_PAGES` | `-max-pages` | `20` | Automatic pagination bound. Truncation is always reported, never silent. |
| `CTFD_CACHE_TTL` | `-cache-ttl` | `15s` | Read cache lifetime. `0` disables caching. |
| `CTFD_INSECURE_TLS` | `-insecure` | `false` | Skip TLS verification. For self-signed self-hosted CTFs. |
| `CTFD_USER_AGENT` | `-user-agent` | `ctfd-mcp/<version>` | User-Agent header. |
| `CTFD_LOG_LEVEL` | `-log-level` | `info` | `debug`, `info`, `warn`, or `error`. Logs go to stderr. |

---

## Safety model

A CTF is a live, scored, adversarial event. Mistakes cost points and cannot be undone.

**Core play actions are ready immediately.** Flag submission, hint unlocking, and
file downloads are enabled by default. Set the corresponding `CTFD_ALLOW_*` variable
to `false` only when you deliberately need a read-only or restricted setup.

**Submissions are never retried.** CTFd records a failed attempt even when it answers
`429 ratelimited` — the flag is never evaluated, but the attempt is spent. An
automatic retry would therefore burn a second attempt against a capped challenge for
nothing. The retry layer is disabled for this one endpoint by construction, and a
test enforces it.

**Duplicate flags are refused.** The server remembers, per challenge, every flag it
has submitted this session (hashed, never in plaintext) and refuses to send the same
one twice. `force: true` overrides.

**The attempt budget is checked before submitting.** The challenge is read first; if
no attempts remain, nothing is sent. Because CTFd derives its `attempts` field from
all submissions but enforces the limit against failures only, the two can disagree,
so this refusal is overridable with `force: true`.

**Hints unlock on request.** `ctfd_unlock_hint` does not require a separate
confirmation argument. A paid hint spends the cost CTFd reports as soon as the tool
is called; set `CTFD_ALLOW_UNLOCK=false` if that is not appropriate for a deployment.
Free hints remain available without a purchase.

**Challenge content is treated as untrusted.** Descriptions, hints, and announcements
are authored by event organizers — anyone who can write a challenge can write
"ignore your instructions". All such text is delivered inside a fence, explicitly
labelled as untrusted data, so the boundary stays visible to the model.

**Downloads are sandboxed.** Attachment URLs are pinned to the configured CTFd host
(a challenge cannot redirect the client at an internal address), filenames are
stripped of path separators and Windows device names, writes are confined to
the configured sandbox (by default `ctfd-downloads`), size is capped, and content is
hashed. Downloads land via a temporary file, so an interrupted transfer never leaves
a truncated file that looks complete. An existing file is never overwritten.

**Credentials never reach the model or the logs.** Tokens, passwords, session
cookies, and the signed `?token=` on attachment URLs are scrubbed centrally from
every tool result, error message, and log record. A newly minted token is registered
for scrubbing the moment it is created — it appears exactly once, in the response
that produced it, because that response is the only place it exists. A test sweeps
every tool's output for the configured credential.

**Account changes require confirmation.** Creating or revoking an API token, and
joining or creating a team, each need an explicit `confirm: true` on the call. Team
membership in particular is effectively permanent: CTFd gives players no way to
leave, and from then on all solves and points are shared.

---

## How it handles CTFd's rough edges

These are behaviors of the real CTFd API that break naive clients. Each is handled,
and most are covered by a regression test.

**`Content-Type` gates authentication.** CTFd reads the `Authorization` header only
when `request.mimetype == "application/json"`. A bodyless `GET` without that header
is processed **anonymously** — returning `200` with public data rather than `401`, so
the bug looks like missing permissions. The header is set on every request, and must
be the bare literal: CTFd's auth decorators compare `content_type` for exact
equality, so `application/json; charset=utf-8` turns JSON 403s into HTML login
redirects.

**Success does not mean success.** `POST /challenges/attempt` returns
`{"success": true}` for *every* outcome, varying only the HTTP status: `200` for
correct/incorrect/already-solved, `403` for paused and for an exhausted budget, `429`
for rate limiting. The real outcome is `data.status`, which is read regardless of
status code.

**Only some endpoints paginate.** `/users`, `/teams`, `/submissions`, and `/comments`
do. `/challenges`, `/scoreboard`, `/notifications`, and the `/solves` endpoints
return complete arrays. Pagination is followed automatically up to `CTFD_MAX_PAGES`,
and hitting that bound is reported rather than passed off as a complete result.

**Error bodies are inconsistent.** Field errors arrive as `{"field": ["msg"]}` from
marshmallow validation but as `{"field": "msg"}` from `/unlocks`. Both decode.

**`null` is not zero.** When organizers hide scores or accounts, solve counts come
back as JSON `null`, which means "hidden", not "nobody solved it". These stay as
pointers and render as `hidden`.

**Tags change shape.** The challenge *list* returns tags as `{"value": "..."}`
objects; challenge *detail* returns plain strings. Both normalize to strings.

**Rank is an object key.** `/scoreboard/top/{n}` returns an object keyed by
stringified rank rather than an array, so Go map iteration would scramble the order.
Keys are parsed and sorted.

**Notifications have no `ORDER BY`.** CTFd returns them in database-defined order, so
"newest first" is only true if the client sorts. It does.

**Redirects mean failure for API calls, and success for downloads.** An API request
that redirects is CTFd bouncing you to `/login` (unauthenticated) or `/teams`
(team mode, no team) — following it yields HTML and a confusing decode error, so API
redirects are not followed and surface as auth errors. File downloads *do* follow
redirects, because an S3 storage backend answers with a 302 to a presigned URL; Go
drops credentials on cross-host redirects, so CTFd's token is not forwarded to S3.

**A hidden scoreboard is a 403 or a 404.** `score_visibility=hidden` gives 403;
`score_visibility=admins` gives 404 to mask the endpoint's existence. Both are
reported as "hidden by the organizers", with a pointer to `ctfd_my_progress`, which
reads your own solves and is unaffected by scoreboard visibility.

**CSRF has two different channels.** Cookie-authenticated writes need the session's
nonce — in the `CSRF-Token` header for JSON requests, but in a `nonce` **form field**
for form posts like login and team join. A successful login calls
`session.regenerate()`, which rotates the nonce, so the one scraped before logging in
is already dead by the time you'd use it. An `Authorization` header skips all of this.

**A rejected nonce costs nothing.** CTFd checks the nonce in a `before_request` hook,
so a rejection happens before the handler runs: no submission is recorded and no
attempt is consumed. That makes exactly one automatic retry with a refreshed nonce
safe even for flag submission, which is otherwise never retried.

**Admin-only endpoints are simply absent.** `GET /hints` (list),
`/challenges/types`, `/submissions`, `/configs`, `/statistics`, and the rest are
`@admins_only` and would only ever return 403 for a competitor, so they are not
exposed as tools.

---

## Troubleshooting

**Everything returns 403, or reads come back empty.**
Usually an expired token — CTFd tokens expire 30 days after creation by default.
Generate a new one. Run with `CTFD_LOG_LEVEL=debug` to see per-request status codes.

**"The response was not a CTFd API JSON envelope."**
`CTFD_URL` is probably not pointing at the CTFd root. It should be the site root
(`https://ctf.example.com`), not `/api/v1` and not a login page.

**"could not reach CTFd" on a self-hosted instance.**
If it uses a self-signed certificate, set `CTFD_INSECURE_TLS=true`. This disables
certificate verification, so only do it for an instance you control.

**Submission says it is disabled.**
It was explicitly disabled. Remove `CTFD_ALLOW_SUBMIT=false` (or start with
`-allow-submit=true`) and restart the MCP client so the server picks up the change.

**Login fails with "CTFd rejected the username or password".**
Try the same credentials in a browser. If they work there, check whether the account
was created through an OAuth provider — such accounts have no password, and you need
an API token instead. Note that CTFd accepts either a username or an email address
in `CTFD_USERNAME`.

**Login worked, but writes fail with a CSRF error.**
The server refreshes a stale nonce and retries once automatically, so a persistent
failure usually means a proxy is stripping the `CSRF-Token` header or rewriting
cookies. Switching to `CTFD_TOKEN` sidesteps CSRF entirely.

**The CTF has not started, or has ended.**
CTFd's `during_ctf_time_only` gate returns 403 on the challenge endpoints outside
event hours. The message names the reason.

**Team mode with no team.**
CTFd rejects challenge reads and submissions with 403 until the account joins a team.
`ctfd_whoami` reports this explicitly.

---

## Development

```bash
go test ./...              # full suite, including a subprocess end-to-end test
go test -short ./...       # skips the tests that compile a binary
go vet ./...
make race                  # needs cgo and a C compiler
```

CI runs on every push and pull request: build, vet, and tests on Linux **and**
Windows (Windows matters — `internal/ctfd/download.go` has real platform-specific
filename handling), plus the race detector, `gofmt`, `go mod tidy`, `staticcheck`,
and a cross-compile of all six release targets.

The tests run entirely against `httptest` stand-ins built from CTFd's actual
response shapes; nothing touches a real instance. `cmd/ctfd-mcp/e2e_test.go`
compiles the real binary and drives it over stdio the way an MCP client does, and
`internal/mcpserver/compat_test.go` replays CTFd 3.6.1's older response shapes to
keep version support from regressing.

### Layout

```
cmd/ctfd-mcp/        entry point, logging, signal handling, e2e test
internal/config/     env + flag loading and validation
internal/ctfd/       CTFd API client: transport, retries, models, endpoints
internal/mcpserver/  MCP tool definitions and output rendering
internal/redact/     credential scrubbing
```

The layering is deliberate: retries, rate limiting, size caps, and error
classification all live in `internal/ctfd`, so every tool inherits them and no tool
handler can forget to apply one.

---

## License

[MIT](LICENSE).
