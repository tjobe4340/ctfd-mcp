package ctfd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// The structs below mirror CTFd 3.x API responses exactly as its marshmallow
// schemas and API handlers emit them. Field presence varies by the caller's
// privilege ("view" in CTFd terms), so anything a player may not receive is a
// pointer or is tolerant of absence.
//
// Verified against CTFd 3.7.7 source: CTFd/api/v1/*.py and CTFd/schemas/*.py.

// ChallengeListItem is one entry from GET /api/v1/challenges.
//
// This endpoint returns a bare array, not a paginated envelope, and its item
// shape is hand-built in the handler rather than produced by a schema — so it
// is deliberately narrower than ChallengeDetail.
type ChallengeListItem struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    int    `json:"value"`
	Category string `json:"category"`
	// Solves is null when the organizer has hidden scores or accounts, which
	// is different from a challenge nobody has solved.
	Solves     *int `json:"solves"`
	SolvedByMe bool `json:"solved_by_me"`
	// Tags arrive as objects here ({"value": "..."}), unlike ChallengeDetail
	// where they are plain strings. Both are normalized by TagValues.
	Tags []Tag `json:"tags"`
	// Template and Script are front-end asset paths, of no use to a model.
	Template string `json:"template,omitempty"`
	Script   string `json:"script,omitempty"`
}

// IsAnonymized reports whether CTFd redacted this entry because the player has
// not met its prerequisites. Such entries have type "hidden" and literal "???"
// placeholders rather than real values.
func (c ChallengeListItem) IsAnonymized() bool {
	return c.Type == "hidden" || c.Name == "???"
}

// Tag is a challenge tag as returned in list responses.
type Tag struct {
	Value string `json:"value"`
}

// TagValues flattens tags to plain strings.
func TagValues(tags []Tag) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Value != "" {
			out = append(out, t.Value)
		}
	}
	return out
}

// ChallengeDetail is GET /api/v1/challenges/{id}.
//
// The payload is the challenge plugin's read() output merged with
// visibility-dependent extras. Standard and dynamic-value challenges share a
// base; dynamic ones add Initial/Decay/Minimum/Function.
type ChallengeDetail struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Value       int    `json:"value"`
	Description string `json:"description"`
	// Attribution credits the challenge author. Added in CTFd 3.7.
	Attribution string `json:"attribution"`
	// ConnectionInfo is the netcat/URL target for challenges with a live
	// service, e.g. "nc chal.example.com 1337".
	ConnectionInfo string `json:"connection_info"`
	// NextID suggests the challenge to attempt next, when the organizer has
	// configured a sequence.
	NextID      *int   `json:"next_id"`
	Category    string `json:"category"`
	State       string `json:"state"`
	MaxAttempts int    `json:"max_attempts"`
	Type        string `json:"type"`

	// Solves is null when scores or accounts are hidden.
	Solves     *int `json:"solves"`
	SolvedByMe bool `json:"solved_by_me"`
	// Attempts counts this account's submissions against this challenge,
	// correct and incorrect alike.
	Attempts int `json:"attempts"`

	// Files are ready-to-use absolute or root-relative download URLs. For an
	// authenticated request CTFd appends a signed ?token= parameter.
	Files []string `json:"files"`
	// Tags are plain strings in this response.
	Tags  []string        `json:"tags"`
	Hints []ChallengeHint `json:"hints"`

	// Dynamic-value challenge fields, absent on standard challenges.
	Initial  *int    `json:"initial,omitempty"`
	Decay    *int    `json:"decay,omitempty"`
	Minimum  *int    `json:"minimum,omitempty"`
	Function *string `json:"function,omitempty"`

	// TypeData describes the challenge plugin. Only its Name is interesting.
	TypeData *ChallengeTypeData `json:"type_data,omitempty"`

	// View is a fully rendered HTML fragment. It duplicates every other field
	// at great length, so it is decoded and then discarded rather than being
	// passed to the model.
	View string `json:"view,omitempty"`
}

// AttemptsRemaining estimates how many submissions are left, and reports
// whether the challenge is capped at all.
//
// It is an estimate, not an authority. CTFd populates Attempts from the
// Submissions table (correct and incorrect alike) but enforces MaxAttempts
// against the Fails table only, so on a challenge with a correct submission
// the two disagree and this under-reports. That is the safe direction, and
// callers should let a user override a refusal based on it.
func (c ChallengeDetail) AttemptsRemaining() (remaining int, capped bool) {
	if c.MaxAttempts <= 0 {
		return 0, false
	}
	r := c.MaxAttempts - c.Attempts
	if r < 0 {
		r = 0
	}
	return r, true
}

// ChallengeTypeData identifies the challenge plugin backing a challenge.
type ChallengeTypeData struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ChallengeHint is a hint as embedded in a challenge detail response.
//
// CTFd emits one of two shapes: {id, cost, title} while locked, and
// {id, cost, content} once unlocked or after the CTF ends. Content being empty
// while Cost is non-zero therefore means "still locked".
type ChallengeHint struct {
	ID      int    `json:"id"`
	Cost    int    `json:"cost"`
	Title   string `json:"title,omitempty"`
	Content string `json:"content,omitempty"`
}

// Unlocked reports whether the hint's content is available.
func (h ChallengeHint) Unlocked() bool { return h.Content != "" }

// Hint is GET /api/v1/hints/{id}. Content and HTML are populated only in the
// "unlocked" view.
type Hint struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Type        string `json:"type"`
	ChallengeID int    `json:"challenge_id"`
	Cost        int    `json:"cost"`
	Content     string `json:"content,omitempty"`
	HTML        string `json:"html,omitempty"`
}

// Unlocked reports whether the hint content came back.
func (h Hint) Unlocked() bool { return h.Content != "" }

// SolutionRef is GET /api/v1/challenges/{id}/solution.
//
// ID is null unless the account is allowed to read the solution, so State is
// the field that explains why. CTFd 3.8 and later only.
type SolutionRef struct {
	// ID identifies the solution, or is nil when it is not readable.
	ID *int `json:"id"`
	// State is "hidden", "visible", or "solved". "solved" means the solution
	// exists but only unlocks once this account solves the challenge.
	State string `json:"state"`
}

// Available reports whether a solution can be fetched right now.
func (s SolutionRef) Available() bool { return s.ID != nil }

// Explain describes why a solution is not readable.
func (s SolutionRef) Explain(solvedByMe bool) string {
	switch {
	case s.Available():
		return ""
	case s.State == "" || s.State == "hidden":
		return "No official solution has been published for this challenge, or the organizers have it hidden."
	case s.State == "solved" && !solvedByMe:
		return "An official solution exists but unlocks only once you have solved the challenge yourself."
	case s.State == "solved":
		return "An official solution exists and should unlock now that the challenge is solved; if it does not, the organizers may still be withholding it."
	default:
		return fmt.Sprintf("An official solution exists but is not readable (state %q).", s.State)
	}
}

// Solution is an official writeup published by the organizers.
//
// Content is populated only in the "unlocked" view. Solutions have their own
// unlock records, separate from hints, though unlocking one costs nothing.
type Solution struct {
	ID          int    `json:"id"`
	ChallengeID int    `json:"challenge_id"`
	State       string `json:"state"`
	Content     string `json:"content,omitempty"`
	HTML        string `json:"html,omitempty"`
}

// Unlocked reports whether the solution's content came back.
func (s Solution) Unlocked() bool { return s.Content != "" || s.HTML != "" }

// Rating is this account's rating of a challenge.
type Rating struct {
	ID          int `json:"id"`
	UserID      int `json:"user_id"`
	ChallengeID int `json:"challenge_id"`
	// Value is +1 or -1.
	Value  int    `json:"value"`
	Review string `json:"review"`
	Date   string `json:"date"`
}

// OwnSubmission is one of this account's own submissions, including the text
// that was submitted. Available only when the organizers enable
// view_self_submissions.
type OwnSubmission struct {
	ID          int `json:"id"`
	ChallengeID int `json:"challenge_id"`
	// Provided is the string that was submitted.
	Provided string `json:"provided"`
	Type     string `json:"type"`
	Date     string `json:"date"`
}

// Correct reports whether this submission was accepted.
func (s OwnSubmission) Correct() bool { return s.Type == "correct" }

// Unlock is the object returned by POST /api/v1/unlocks.
type Unlock struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	TeamID *int   `json:"team_id"`
	Target int    `json:"target"`
	Type   string `json:"type"`
	Date   string `json:"date"`
}

// AttemptStatus is the outcome of a flag submission, taken from
// data.status in the POST /api/v1/challenges/attempt response.
type AttemptStatus string

const (
	// AttemptCorrect means the flag was accepted and the solve recorded.
	AttemptCorrect AttemptStatus = "correct"
	// AttemptIncorrect means the flag was rejected. A failed attempt is
	// recorded against the account.
	AttemptIncorrect AttemptStatus = "incorrect"
	// AttemptAlreadySolved means this account had already solved it; no
	// attempt is consumed.
	AttemptAlreadySolved AttemptStatus = "already_solved"
	// AttemptPaused means the competition is paused. HTTP 403.
	AttemptPaused AttemptStatus = "paused"
	// AttemptRateLimited means too many wrong flags per minute. HTTP 429.
	//
	// CTFd still records a failed attempt in this case, so a rate-limited
	// submission costs an attempt without ever being evaluated.
	AttemptRateLimited AttemptStatus = "ratelimited"
	// AttemptAuthRequired means the request was unauthenticated. HTTP 403.
	AttemptAuthRequired AttemptStatus = "authentication_required"
)

// AttemptResult is the decoded data block of a submission response.
type AttemptResult struct {
	Status  AttemptStatus `json:"status"`
	Message string        `json:"message"`

	// HTTPStatus is the transport status that accompanied the result, kept
	// because CTFd signals paused (403) and rate-limited (429) out of band
	// while still setting success:true.
	HTTPStatus int `json:"-"`
}

// Solved reports whether the challenge is solved as a result of, or prior to,
// this submission.
func (a AttemptResult) Solved() bool {
	return a.Status == AttemptCorrect || a.Status == AttemptAlreadySolved
}

// ConsumedAttempt reports whether CTFd recorded a failed attempt for this
// submission. Rate-limited submissions count even though they were never
// evaluated.
func (a AttemptResult) ConsumedAttempt() bool {
	return a.Status == AttemptIncorrect || a.Status == AttemptRateLimited
}

// User is a CTFd user. Email and Language appear only in the "self" view from
// GET /api/v1/users/me.
type User struct {
	ID          int            `json:"id"`
	Name        string         `json:"name"`
	Email       string         `json:"email,omitempty"`
	Language    string         `json:"language,omitempty"`
	Website     string         `json:"website"`
	Country     string         `json:"country"`
	Affiliation string         `json:"affiliation"`
	BracketID   *int           `json:"bracket_id"`
	OAuthID     *int           `json:"oauth_id"`
	TeamID      *int           `json:"team_id"`
	Fields      []CustomField  `json:"fields,omitempty"`
	Extra       map[string]any `json:"-"`
}

// Team is a CTFd team. Members is a list of user IDs.
type Team struct {
	ID          int           `json:"id"`
	Name        string        `json:"name"`
	Email       string        `json:"email,omitempty"`
	Website     string        `json:"website"`
	Country     string        `json:"country"`
	Affiliation string        `json:"affiliation"`
	BracketID   *int          `json:"bracket_id"`
	OAuthID     *int          `json:"oauth_id"`
	CaptainID   *int          `json:"captain_id"`
	Members     []int         `json:"members"`
	Fields      []CustomField `json:"fields,omitempty"`
}

// CustomField is an organizer-defined profile field.
type CustomField struct {
	Value       any    `json:"value"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
	FieldID     int    `json:"field_id,omitempty"`
	Type        string `json:"type,omitempty"`
}

// Submission is one solve or failed attempt, from the /solves and /fails
// endpoints. The "user" view omits the submitted string itself.
type Submission struct {
	ID          int              `json:"id"`
	ChallengeID int              `json:"challenge_id"`
	Challenge   *SubmissionChal  `json:"challenge"`
	User        *SubmissionActor `json:"user"`
	Team        *SubmissionActor `json:"team"`
	Date        string           `json:"date"`
	Type        string           `json:"type"`
}

// SubmissionChal is the nested challenge summary on a submission.
type SubmissionChal struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Value    int    `json:"value"`
}

// SubmissionActor is the nested user or team summary on a submission.
type SubmissionActor struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Award is a manual point adjustment. Hint unlocks appear here as negative
// values, which is how spending points shows up in an account's history.
type Award struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Value       int    `json:"value"`
	Icon        string `json:"icon"`
	UserID      *int   `json:"user_id"`
	TeamID      *int   `json:"team_id"`
	Date        string `json:"date"`
}

// Notification is an organizer announcement.
type Notification struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Date    string `json:"date"`
	HTML    string `json:"html,omitempty"`
	UserID  *int   `json:"user_id"`
	TeamID  *int   `json:"team_id"`
}

// ScoreboardEntry is one row of GET /api/v1/scoreboard.
//
// AccountType is "user" or "team" depending on the event's mode, and Members
// is populated only in team mode.
type ScoreboardEntry struct {
	Pos         int             `json:"pos"`
	AccountID   int             `json:"account_id"`
	AccountURL  string          `json:"account_url"`
	AccountType string          `json:"account_type"`
	OAuthID     *int            `json:"oauth_id"`
	Name        string          `json:"name"`
	Score       int             `json:"score"`
	BracketID   *int            `json:"bracket_id"`
	BracketName *string         `json:"bracket_name"`
	Members     []ScoreboardMem `json:"members,omitempty"`
}

// ScoreboardMem is a team member's contribution, present in team mode.
type ScoreboardMem struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Score       int     `json:"score"`
	OAuthID     *int    `json:"oauth_id"`
	BracketID   *int    `json:"bracket_id"`
	BracketName *string `json:"bracket_name"`
}

// ScoreboardDetailEntry is one account's score timeline from
// GET /api/v1/scoreboard/top/{count}.
type ScoreboardDetailEntry struct {
	// Pos is the 1-based rank. CTFd encodes it as the object key rather than
	// a field, so it is filled in during decoding.
	Pos         int            `json:"-"`
	ID          int            `json:"id"`
	AccountURL  string         `json:"account_url"`
	Name        string         `json:"name"`
	Score       int            `json:"score"`
	BracketID   *int           `json:"bracket_id"`
	BracketName *string        `json:"bracket_name"`
	Solves      []TimedSolve   `json:"solves"`
	Extra       map[string]any `json:"-"`
}

// TimedSolve is one scoring event on a timeline. ChallengeID is null for
// awards, which is how point adjustments are distinguished from solves.
type TimedSolve struct {
	ChallengeID *int   `json:"challenge_id"`
	AccountID   int    `json:"account_id"`
	TeamID      *int   `json:"team_id"`
	UserID      *int   `json:"user_id"`
	Value       int    `json:"value"`
	Date        string `json:"date"`
}

// IsAward reports whether this timeline entry is an award rather than a solve.
func (t TimedSolve) IsAward() bool { return t.ChallengeID == nil }

// scoreboardDetail decodes the top-N response, which CTFd returns as an object
// keyed by stringified rank ("1", "2", ...) rather than as an array. The keys
// carry the ordering, so they must be parsed and sorted rather than relying on
// JSON object order.
func decodeScoreboardDetail(raw json.RawMessage) ([]ScoreboardDetailEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// An empty scoreboard serializes as [] rather than {}.
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "[]" || trimmed == "null" {
		return nil, nil
	}

	var byPos map[string]ScoreboardDetailEntry
	if err := json.Unmarshal(raw, &byPos); err != nil {
		return nil, fmt.Errorf("decoding scoreboard detail: %w", err)
	}

	out := make([]ScoreboardDetailEntry, 0, len(byPos))
	for k, v := range byPos {
		pos, err := strconv.Atoi(k)
		if err != nil {
			// A non-numeric key is not something CTFd produces; skip rather
			// than failing the whole call.
			continue
		}
		v.Pos = pos
		out = append(out, v)
	}
	sortByPos(out)
	return out, nil
}

func sortByPos(e []ScoreboardDetailEntry) {
	// Insertion sort: the list is capped at 50 by CTFd, so this is both
	// faster than sort.Slice and allocation-free.
	for i := 1; i < len(e); i++ {
		for j := i; j > 0 && e[j].Pos < e[j-1].Pos; j-- {
			e[j], e[j-1] = e[j-1], e[j]
		}
	}
}
