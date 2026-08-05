package ctfd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// This file covers the player-reachable CTFd API. Endpoints gated by
// @admins_only in CTFd 3.7 (GET /hints, GET /challenges/types, /submissions,
// /configs, /flags, /tags, /files, /comments, the whole /statistics namespace)
// are intentionally absent: calling them with a competitor token only ever
// returns 403.

// ChallengeFilter narrows GET /api/v1/challenges. CTFd validates `field`
// against a fixed enum and rejects anything else with a 400.
type ChallengeFilter struct {
	Name     string
	Category string
	Type     string
	// Q is a substring search applied to the column named by Field.
	Q string
	// Field must be one of name, description, category, type, state.
	Field string
}

// ValidChallengeFields lists the columns CTFd will search with `q`.
var ValidChallengeFields = []string{"name", "description", "category", "type", "state"}

func (f ChallengeFilter) values() (url.Values, error) {
	q := url.Values{}
	if f.Name != "" {
		q.Set("name", f.Name)
	}
	if f.Category != "" {
		q.Set("category", f.Category)
	}
	if f.Type != "" {
		q.Set("type", f.Type)
	}
	if f.Q != "" {
		field := f.Field
		if field == "" {
			field = "name"
		}
		if !contains(ValidChallengeFields, field) {
			return nil, fmt.Errorf("ctfd: invalid search field %q: must be one of %s", field, strings.Join(ValidChallengeFields, ", "))
		}
		// CTFd requires both or neither; sending q alone is silently ignored.
		q.Set("q", f.Q)
		q.Set("field", field)
	}
	return q, nil
}

// Challenges lists challenges visible to the current account.
//
// This endpoint is not paginated: CTFd returns every visible challenge in one
// array.
func (c *Client) Challenges(ctx context.Context, f ChallengeFilter) ([]ChallengeListItem, error) {
	q, err := f.values()
	if err != nil {
		return nil, err
	}
	var out []ChallengeListItem
	if _, err := c.get(ctx, "challenges", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Challenge fetches one challenge's full detail.
func (c *Client) Challenge(ctx context.Context, id int) (*ChallengeDetail, error) {
	var out ChallengeDetail
	if _, err := c.get(ctx, "challenges/"+strconv.Itoa(id), nil, &out); err != nil {
		return nil, err
	}
	// The rendered HTML view duplicates every other field at length and is
	// useless to a model; drop it before it can reach anyone's context.
	out.View = ""
	return &out, nil
}

// ChallengeSolves lists the accounts that solved a challenge. It returns a
// 403-class error when the organizer has hidden accounts or scores.
func (c *Client) ChallengeSolves(ctx context.Context, id int) ([]ChallengeSolver, error) {
	var out []ChallengeSolver
	if _, err := c.get(ctx, "challenges/"+strconv.Itoa(id)+"/solves", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ChallengeSolver is one entry of a challenge's solve list.
type ChallengeSolver struct {
	AccountID   int    `json:"account_id"`
	Name        string `json:"name"`
	Date        string `json:"date"`
	AccountURL  string `json:"account_url"`
	BracketID   *int   `json:"bracket_id"`
	BracketName string `json:"bracket_name"`
}

// Attempt submits a flag.
//
// This is the only state-changing, attempt-consuming call in the client, and
// it is never retried. CTFd answers with success:true and a status string in
// every case, varying only the HTTP code: 200 for correct/incorrect/
// already_solved, 403 for paused and for an exhausted attempt budget, and 429
// for rate limiting. A rate-limited submission is still recorded as a failure
// by CTFd, so a retry would consume a second attempt without the flag ever
// being evaluated.
func (c *Client) Attempt(ctx context.Context, challengeID int, submission string) (*AttemptResult, error) {
	body := map[string]any{
		"challenge_id": challengeID,
		"submission":   submission,
	}
	var out AttemptResult
	res, err := c.do(ctx, request{
		method:            http.MethodPost,
		path:              "challenges/attempt",
		body:              body,
		idempotent:        false,
		useSubmitLimiter:  true,
		dataOnErrorStatus: true,
	}, &out)
	if err != nil {
		return nil, err
	}
	out.HTTPStatus = res.Status

	// Any submission may change solve state, score, and scoreboard position.
	c.InvalidateCache()

	if out.Status == "" {
		return nil, &Error{
			Kind: KindDecode, StatusCode: res.Status, Method: http.MethodPost, Path: "challenges/attempt",
			Message: "CTFd did not report a submission status",
			Body:    truncate(string(res.Data), 512),
		}
	}
	return &out, nil
}

// Hint fetches a hint. Content is present only when the hint is free, already
// unlocked, or the CTF has ended.
func (c *Client) Hint(ctx context.Context, id int) (*Hint, error) {
	var out Hint
	if _, err := c.get(ctx, "hints/"+strconv.Itoa(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unlock target types accepted by POST /api/v1/unlocks.
const (
	// UnlockHints costs the hint's price, recorded as a negative award.
	UnlockHints = "hints"
	// UnlockSolutions is free: CTFd records the unlock but performs no score
	// check and creates no award. It exists so organizers can see who read a
	// writeup, not to charge for it.
	UnlockSolutions = "solutions"
)

// UnlockHint spends points to unlock a hint.
//
// CTFd rejects an unaffordable or already-unlocked target with HTTP 400 and a
// field error, which surfaces here as a KindValidation error.
func (c *Client) UnlockHint(ctx context.Context, hintID int) (*Unlock, error) {
	return c.unlock(ctx, hintID, UnlockHints)
}

// UnlockSolution reveals an official solution. Unlike a hint unlock this costs
// nothing; CTFd only records that the solution was viewed.
func (c *Client) UnlockSolution(ctx context.Context, solutionID int) (*Unlock, error) {
	return c.unlock(ctx, solutionID, UnlockSolutions)
}

func (c *Client) unlock(ctx context.Context, target int, kind string) (*Unlock, error) {
	var out Unlock
	_, err := c.do(ctx, request{
		method:     http.MethodPost,
		path:       "unlocks",
		body:       map[string]any{"target": target, "type": kind},
		idempotent: false,
	}, &out)
	if err != nil {
		return nil, err
	}
	// A hint unlock deducts points via a negative award, changing score and
	// rank; both kinds change what the challenge endpoints return.
	c.InvalidateCache()
	return &out, nil
}

// ChallengeSolution reports whether an official solution exists for a
// challenge and whether the current account may read it.
//
// Added in CTFd 3.8; earlier versions have no such route and answer 404.
func (c *Client) ChallengeSolution(ctx context.Context, challengeID int) (*SolutionRef, error) {
	var out SolutionRef
	if _, err := c.get(ctx, "challenges/"+strconv.Itoa(challengeID)+"/solution", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Solution fetches an official solution's content.
//
// CTFd gates these behind their own unlock records, separate from hints, so a
// solution may come back without content until UnlockSolution is called.
func (c *Client) Solution(ctx context.Context, solutionID int) (*Solution, error) {
	var out Solution
	if _, err := c.get(ctx, "solutions/"+strconv.Itoa(solutionID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RateChallenge records or replaces this account's rating for a challenge.
//
// CTFd accepts only +1 or -1, requires the challenge to already be solved, and
// caps the review at 2000 characters. Added in CTFd 3.8.
func (c *Client) RateChallenge(ctx context.Context, challengeID, value int, review string) (*Rating, error) {
	if value != 1 && value != -1 {
		return nil, fmt.Errorf("ctfd: rating value must be 1 or -1, got %d", value)
	}
	if len(review) > 2000 {
		return nil, fmt.Errorf("ctfd: review is %d characters; CTFd allows at most 2000", len(review))
	}
	body := map[string]any{"value": value}
	if review != "" {
		body["review"] = review
	}

	var out Rating
	// PUT here is a genuine upsert: re-sending the same rating replaces it
	// rather than adding another, so it is safe to retry.
	if _, err := c.do(ctx, request{
		method:     http.MethodPut,
		path:       "challenges/" + strconv.Itoa(challengeID) + "/ratings",
		body:       body,
		idempotent: true,
	}, &out); err != nil {
		return nil, err
	}
	c.InvalidateCache()
	return &out, nil
}

// MySubmissions returns this account's own submissions, including the strings
// that were submitted.
//
// CTFd hides this behind the view_self_submissions config and answers 403 when
// it is off, which is the default. challengeID of 0 means all challenges.
func (c *Client) MySubmissions(ctx context.Context, challengeID int) ([]OwnSubmission, error) {
	q := url.Values{}
	if challengeID > 0 {
		q.Set("challenge_id", strconv.Itoa(challengeID))
	}
	var out []OwnSubmission
	if _, err := c.get(ctx, "users/me/submissions", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Me returns the authenticated user.
func (c *Client) Me(ctx context.Context) (*User, error) {
	var out User
	if _, err := c.get(ctx, "users/me", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MyTeam returns the authenticated user's team.
//
// In user mode, or when the account has not joined a team, CTFd's
// @require_team decorator answers 403; callers should treat a forbidden result
// as "no team" rather than an error.
func (c *Client) MyTeam(ctx context.Context) (*Team, error) {
	var out Team
	if _, err := c.get(ctx, "teams/me", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MySolves returns the current account's solves.
func (c *Client) MySolves(ctx context.Context) ([]Submission, error) {
	return c.submissions(ctx, "users/me/solves")
}

// MyFails returns the current account's failed submissions.
func (c *Client) MyFails(ctx context.Context) ([]Submission, error) {
	return c.submissions(ctx, "users/me/fails")
}

// MyAwards returns the current account's awards, including the negative
// awards CTFd creates when hints are unlocked.
func (c *Client) MyAwards(ctx context.Context) ([]Award, error) {
	return c.awards(ctx, "users/me/awards")
}

// TeamSolves returns the current team's solves.
func (c *Client) TeamSolves(ctx context.Context) ([]Submission, error) {
	return c.submissions(ctx, "teams/me/solves")
}

// TeamFails returns the current team's failed submissions.
func (c *Client) TeamFails(ctx context.Context) ([]Submission, error) {
	return c.submissions(ctx, "teams/me/fails")
}

// TeamAwards returns the current team's awards.
func (c *Client) TeamAwards(ctx context.Context) ([]Award, error) {
	return c.awards(ctx, "teams/me/awards")
}

// UserSolves returns another user's public solves.
func (c *Client) UserSolves(ctx context.Context, userID int) ([]Submission, error) {
	return c.submissions(ctx, "users/"+strconv.Itoa(userID)+"/solves")
}

// TeamSolvesByID returns another team's public solves.
func (c *Client) TeamSolvesByID(ctx context.Context, teamID int) ([]Submission, error) {
	return c.submissions(ctx, "teams/"+strconv.Itoa(teamID)+"/solves")
}

func (c *Client) submissions(ctx context.Context, path string) ([]Submission, error) {
	var out []Submission
	if _, err := c.get(ctx, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) awards(ctx context.Context, path string) ([]Award, error) {
	var out []Award
	if _, err := c.get(ctx, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// User fetches another user's public profile.
func (c *Client) User(ctx context.Context, id int) (*User, error) {
	var out User
	if _, err := c.get(ctx, "users/"+strconv.Itoa(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Team fetches another team's public profile.
func (c *Client) Team(ctx context.Context, id int) (*Team, error) {
	var out Team
	if _, err := c.get(ctx, "teams/"+strconv.Itoa(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AccountFilter narrows the paginated users and teams listings.
type AccountFilter struct {
	Affiliation string
	Country     string
	Q           string
	// Field must be one of name, website, country, bracket, affiliation.
	Field string
}

// ValidAccountFields lists the columns CTFd will search on users and teams.
var ValidAccountFields = []string{"name", "website", "country", "bracket", "affiliation"}

func (f AccountFilter) values() (url.Values, error) {
	q := url.Values{}
	if f.Affiliation != "" {
		q.Set("affiliation", f.Affiliation)
	}
	if f.Country != "" {
		q.Set("country", f.Country)
	}
	if f.Q != "" {
		field := f.Field
		if field == "" {
			field = "name"
		}
		if !contains(ValidAccountFields, field) {
			return nil, fmt.Errorf("ctfd: invalid search field %q: must be one of %s", field, strings.Join(ValidAccountFields, ", "))
		}
		q.Set("q", f.Q)
		q.Set("field", field)
	}
	return q, nil
}

// Users lists users. This endpoint is paginated (CTFd defaults to 50 per page
// and caps per_page at 100); pages are followed automatically up to MaxPages.
func (c *Client) Users(ctx context.Context, f AccountFilter) ([]User, bool, error) {
	q, err := f.values()
	if err != nil {
		return nil, false, err
	}
	var all []User
	truncated, err := paginate(ctx, c, "users", q, &all)
	return all, truncated, err
}

// Teams lists teams, with the same pagination behavior as Users.
func (c *Client) Teams(ctx context.Context, f AccountFilter) ([]Team, bool, error) {
	q, err := f.values()
	if err != nil {
		return nil, false, err
	}
	var all []Team
	truncated, err := paginate(ctx, c, "teams", q, &all)
	return all, truncated, err
}

// Scoreboard returns the full ranking. It is not paginated, and CTFd caches it
// server-side for 60 seconds, so polling it faster gains nothing.
func (c *Client) Scoreboard(ctx context.Context) ([]ScoreboardEntry, error) {
	var out []ScoreboardEntry
	if _, err := c.get(ctx, "scoreboard", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ScoreboardTop returns the top count accounts with their scoring timelines.
// CTFd clamps count to the range 1..50.
func (c *Client) ScoreboardTop(ctx context.Context, count int) ([]ScoreboardDetailEntry, error) {
	if count < 1 {
		count = 10
	}
	if count > 50 {
		count = 50
	}
	res, err := c.do(ctx, request{
		method:     http.MethodGet,
		path:       "scoreboard/top/" + strconv.Itoa(count),
		idempotent: true,
		cacheKey:   cacheKeyFor("scoreboard/top/"+strconv.Itoa(count), nil),
	}, nil)
	if err != nil {
		return nil, err
	}
	return decodeScoreboardDetail(res.Data)
}

// Notifications returns organizer announcements, newest first.
//
// CTFd applies no ORDER BY to this query, so the wire order is whatever the
// database happened to return. Sorting here rather than trusting that order is
// what makes "newest first" true.
func (c *Client) Notifications(ctx context.Context) ([]Notification, error) {
	var out []Notification
	if _, err := c.get(ctx, "notifications", nil, &out); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Notification fetches one announcement.
func (c *Client) Notification(ctx context.Context, id int) (*Notification, error) {
	var out Notification
	if _, err := c.get(ctx, "notifications/"+strconv.Itoa(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Mode reports whether the event scores individuals or teams.
const (
	ModeUsers = "users"
	ModeTeams = "teams"
)

// DetectMode determines whether the event runs in user or team mode.
//
// CTFd exposes user_mode only through the admin-only /configs endpoint, so it
// is inferred instead: the scoreboard labels every entry with account_type,
// and failing that the presence of a team on the current account is decisive.
func (c *Client) DetectMode(ctx context.Context) (string, error) {
	board, err := c.Scoreboard(ctx)
	if err == nil && len(board) > 0 && board[0].AccountType != "" {
		switch board[0].AccountType {
		case "team":
			return ModeTeams, nil
		case "user":
			return ModeUsers, nil
		}
	}
	// The scoreboard may be hidden or empty before the event opens.
	me, meErr := c.Me(ctx)
	if meErr != nil {
		if err != nil {
			return "", err
		}
		return "", meErr
	}
	if me.TeamID != nil {
		return ModeTeams, nil
	}
	return ModeUsers, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
