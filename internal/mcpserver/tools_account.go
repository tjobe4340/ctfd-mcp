package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// WhoAmIOut describes the authenticated competitor.
type WhoAmIOut struct {
	UserID   int    `json:"user_id"`
	UserName string `json:"user_name"`
	Email    string `json:"email,omitempty"`
	// Mode is "users" or "teams" and determines whether score and rank belong
	// to the individual or the team.
	Mode        string `json:"mode"`
	TeamID      *int   `json:"team_id,omitempty"`
	TeamName    string `json:"team_name,omitempty"`
	Score       *int   `json:"score,omitempty"`
	Rank        *int   `json:"rank,omitempty"`
	TotalRanked int    `json:"total_ranked"`
	Country     string `json:"country,omitempty"`
	Affiliation string `json:"affiliation,omitempty"`
	AuthMethod  string `json:"auth_method"`
	// Warnings lists things that limited what could be reported, such as a
	// hidden scoreboard.
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) registerAccountTools() {
	addTool(s, &mcp.Tool{
		Name:        "ctfd_whoami",
		Title:       "Who am I",
		Annotations: readOnly("Who am I"),
		Description: "Identify the authenticated competitor: user, team (if the event is in team mode), current score, " +
			"and scoreboard rank. Call this first in a session to establish context and confirm credentials work.",
	}, s.whoami)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_my_progress",
		Title:       "My progress",
		Annotations: readOnly("My progress"),
		Description: "The authoritative record of your account's solves, failed submissions, and point awards from CTFd. " +
			"Hint unlocks appear as negative awards. Use this rather than ctfd_session_report when you need the full history, " +
			"not just what this session did.",
	}, s.myProgress)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_lookup_account",
		Title:       "Look up an account",
		Annotations: readOnly("Look up an account"),
		Description: "Look up another competitor or team by ID, or search by name. Returns the profile and, optionally, " +
			"their public solves - useful for seeing which challenges a leading team has already cleared.",
	}, s.lookupAccount)
}

func (s *Server) whoami(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, WhoAmIOut, error) {
	var out WhoAmIOut

	me, err := s.deps.Client.Me(ctx)
	if err != nil {
		return nil, out, err
	}
	out.UserID = me.ID
	out.UserName = me.Name
	out.Email = me.Email
	out.Country = me.Country
	out.Affiliation = me.Affiliation
	out.TeamID = me.TeamID
	out.AuthMethod = s.deps.Client.AuthMethod()
	out.Mode = s.detectMode(ctx, me)

	// The account whose score appears on the scoreboard is the team in team
	// mode and the user otherwise.
	accountID := me.ID
	if out.Mode == ctfd.ModeTeams && me.TeamID != nil {
		accountID = *me.TeamID
	}

	if out.Mode == ctfd.ModeTeams {
		if me.TeamID == nil {
			out.Warnings = append(out.Warnings, "This event is in team mode but your account has not joined a team. Most endpoints, including flag submission, will be rejected until you do.")
		} else if team, terr := s.deps.Client.MyTeam(ctx); terr == nil {
			out.TeamName = team.Name
		} else if !ctfd.IsForbidden(terr) && !ctfd.IsNotFound(terr) {
			s.log.Debug("could not read team", "error", s.red.Error(terr))
		}
	}

	board, berr := s.deps.Client.Scoreboard(ctx)
	switch {
	case berr != nil && (ctfd.IsForbidden(berr) || ctfd.IsNotFound(berr)):
		out.Warnings = append(out.Warnings, "The scoreboard is hidden by the organizers, so score and rank are unavailable.")
	case berr != nil:
		out.Warnings = append(out.Warnings, "Could not read the scoreboard: "+s.red.Error(berr))
	default:
		out.TotalRanked = len(board)
		for _, e := range board {
			if e.AccountID == accountID {
				score, pos := e.Score, e.Pos
				out.Score, out.Rank = &score, &pos
				break
			}
		}
		if out.Score == nil {
			out.Warnings = append(out.Warnings, "Your account does not appear on the scoreboard yet, which is normal before your first solve.")
		}
	}

	return textResult(renderWhoAmI(out)), out, nil
}

// detectMode resolves the event mode once and caches it: it cannot change
// during an event, and it is consulted by several tools.
func (s *Server) detectMode(ctx context.Context, me *ctfd.User) string {
	s.modeOnce.Do(func() {
		if m, err := s.deps.Client.DetectMode(ctx); err == nil {
			s.mode = m
			return
		}
		// Fall back to the weaker signal rather than leaving it unset.
		if me != nil && me.TeamID != nil {
			s.mode = ctfd.ModeTeams
		} else {
			s.mode = ctfd.ModeUsers
		}
	})
	return s.mode
}

func renderWhoAmI(o WhoAmIOut) string {
	var b strings.Builder
	b.WriteString("# Identity\n\n")
	fmt.Fprintf(&b, "- User: %s (ID %d)\n", o.UserName, o.UserID)
	if o.Email != "" {
		fmt.Fprintf(&b, "- Email: %s\n", o.Email)
	}
	fmt.Fprintf(&b, "- Event mode: %s\n", o.Mode)
	if o.TeamName != "" {
		fmt.Fprintf(&b, "- Team: %s (ID %d)\n", o.TeamName, derefInt(o.TeamID))
	} else if o.TeamID != nil {
		fmt.Fprintf(&b, "- Team ID: %d\n", *o.TeamID)
	}
	if o.Score != nil {
		fmt.Fprintf(&b, "- Score: %d points\n", *o.Score)
	}
	if o.Rank != nil {
		fmt.Fprintf(&b, "- Rank: %d of %d\n", *o.Rank, o.TotalRanked)
	}
	if o.Affiliation != "" {
		fmt.Fprintf(&b, "- Affiliation: %s\n", o.Affiliation)
	}
	fmt.Fprintf(&b, "- Authenticated via: %s\n", o.AuthMethod)

	if len(o.Warnings) > 0 {
		b.WriteString("\n## Notes\n")
		for _, w := range o.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	return b.String()
}

// ProgressIn selects whose progress to report.
type ProgressIn struct {
	Scope string `json:"scope,omitempty" jsonschema:"Whose progress to report: 'me' (default) for your own account, or 'team' for your whole team's combined record."`
	// IncludeFails is off by default: on a long event the failure list is much
	// larger than the solve list and rarely what the caller wanted.
	IncludeFails bool `json:"include_fails,omitempty" jsonschema:"Include failed submissions as well as solves. Off by default because the list can be long."`
}

// ProgressOut summarizes an account's record.
type ProgressOut struct {
	Scope      string         `json:"scope"`
	SolveCount int            `json:"solve_count"`
	FailCount  int            `json:"fail_count,omitempty"`
	PointsFrom int            `json:"points_from_solves"`
	AwardTotal int            `json:"award_total"`
	Solves     []SolveEntry   `json:"solves"`
	Fails      []SolveEntry   `json:"fails,omitempty"`
	Awards     []AwardEntry   `json:"awards,omitempty"`
	Categories map[string]int `json:"solves_by_category,omitempty"`
}

// SolveEntry is one solve or failed submission.
type SolveEntry struct {
	ChallengeID   int    `json:"challenge_id"`
	ChallengeName string `json:"challenge_name,omitempty"`
	Category      string `json:"category,omitempty"`
	Value         int    `json:"value,omitempty"`
	Date          string `json:"date,omitempty"`
	By            string `json:"by,omitempty"`
}

// AwardEntry is a manual point adjustment. Hint unlocks appear here with a
// negative value.
type AwardEntry struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
	Value       int    `json:"value"`
	Date        string `json:"date,omitempty"`
}

func (s *Server) myProgress(ctx context.Context, _ *mcp.CallToolRequest, in ProgressIn) (*mcp.CallToolResult, ProgressOut, error) {
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if scope == "" {
		scope = "me"
	}
	if scope != "me" && scope != "team" {
		return nil, ProgressOut{}, fmt.Errorf("invalid scope %q: use 'me' or 'team'", in.Scope)
	}
	out := ProgressOut{Scope: scope, Categories: map[string]int{}}

	var (
		solves []ctfd.Submission
		awards []ctfd.Award
		err    error
	)
	if scope == "team" {
		solves, err = s.deps.Client.TeamSolves(ctx)
		if err != nil {
			if ctfd.IsForbidden(err) {
				return nil, out, fmt.Errorf("no team is associated with this account, or the event is in user mode; use scope='me' instead")
			}
			return nil, out, err
		}
		awards, _ = s.deps.Client.TeamAwards(ctx)
	} else {
		solves, err = s.deps.Client.MySolves(ctx)
		if err != nil {
			return nil, out, err
		}
		awards, _ = s.deps.Client.MyAwards(ctx)
	}

	for _, sv := range solves {
		e := SolveEntry{ChallengeID: sv.ChallengeID, Date: formatDate(sv.Date)}
		if sv.Challenge != nil {
			e.ChallengeName = sv.Challenge.Name
			e.Category = sv.Challenge.Category
			e.Value = sv.Challenge.Value
			out.PointsFrom += sv.Challenge.Value
			out.Categories[sv.Challenge.Category]++
		}
		if sv.User != nil {
			e.By = sv.User.Name
		}
		out.Solves = append(out.Solves, e)
	}
	out.SolveCount = len(out.Solves)

	for _, a := range awards {
		out.AwardTotal += a.Value
		out.Awards = append(out.Awards, AwardEntry{
			Name: a.Name, Description: a.Description, Category: a.Category,
			Value: a.Value, Date: formatDate(a.Date),
		})
	}

	if in.IncludeFails {
		var fails []ctfd.Submission
		if scope == "team" {
			fails, _ = s.deps.Client.TeamFails(ctx)
		} else {
			fails, _ = s.deps.Client.MyFails(ctx)
		}
		for _, f := range fails {
			e := SolveEntry{ChallengeID: f.ChallengeID, Date: formatDate(f.Date)}
			if f.Challenge != nil {
				e.ChallengeName = f.Challenge.Name
				e.Category = f.Challenge.Category
			}
			if f.User != nil {
				e.By = f.User.Name
			}
			out.Fails = append(out.Fails, e)
		}
		out.FailCount = len(out.Fails)
	}

	return textResult(renderProgress(out, in.IncludeFails)), out, nil
}

func renderProgress(o ProgressOut, includeFails bool) string {
	var b strings.Builder
	title := "My progress"
	if o.Scope == "team" {
		title = "Team progress"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "- Solves: %d\n", o.SolveCount)
	fmt.Fprintf(&b, "- Points from solves: %d\n", o.PointsFrom)
	if o.AwardTotal != 0 {
		fmt.Fprintf(&b, "- Net awards: %+d (negative values are hint unlocks)\n", o.AwardTotal)
	}
	if includeFails {
		fmt.Fprintf(&b, "- Failed submissions: %d\n", o.FailCount)
	}

	if len(o.Categories) > 0 {
		cats := make([]string, 0, len(o.Categories))
		for c := range o.Categories {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		b.WriteString("\nBy category: ")
		parts := make([]string, 0, len(cats))
		for _, c := range cats {
			parts = append(parts, fmt.Sprintf("%s %d", c, o.Categories[c]))
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
	}

	if len(o.Solves) > 0 {
		rows := make([][]string, 0, len(o.Solves))
		for _, sv := range o.Solves {
			rows = append(rows, []string{itoa(sv.ChallengeID), sv.ChallengeName, sv.Category, itoa(sv.Value), sv.Date, sv.By})
		}
		section(&b, "Solves", table([]string{"ID", "Challenge", "Category", "Points", "Solved at", "By"}, rows))
	}

	if len(o.Awards) > 0 {
		rows := make([][]string, 0, len(o.Awards))
		for _, a := range o.Awards {
			rows = append(rows, []string{a.Name, a.Category, fmt.Sprintf("%+d", a.Value), a.Date})
		}
		section(&b, "Awards", table([]string{"Name", "Category", "Value", "Date"}, rows))
	}

	if includeFails && len(o.Fails) > 0 {
		rows := make([][]string, 0, len(o.Fails))
		for _, f := range o.Fails {
			rows = append(rows, []string{itoa(f.ChallengeID), f.ChallengeName, f.Category, f.Date, f.By})
		}
		section(&b, "Failed submissions", table([]string{"ID", "Challenge", "Category", "At", "By"}, rows))
	}

	if o.SolveCount == 0 {
		b.WriteString("\nNo solves recorded yet.\n")
	}
	return b.String()
}

// LookupIn selects an account to look up.
type LookupIn struct {
	AccountID int    `json:"account_id,omitempty" jsonschema:"Numeric ID of the user or team to fetch. Provide this or search."`
	Search    string `json:"search,omitempty" jsonschema:"Name substring to search for, when the ID is unknown."`
	Kind      string `json:"kind,omitempty" jsonschema:"Whether to look up a 'user' or a 'team'. Defaults to whichever matches the event mode."`
	// IncludeSolves costs an extra request, so it is opt-in.
	IncludeSolves bool `json:"include_solves,omitempty" jsonschema:"Also fetch this account's public solves. Requires an account_id."`
}

// LookupOut is the result of an account lookup.
type LookupOut struct {
	Kind      string        `json:"kind"`
	Matches   []AccountInfo `json:"matches"`
	Truncated bool          `json:"truncated,omitempty"`
	Solves    []SolveEntry  `json:"solves,omitempty"`
}

// AccountInfo is a public profile.
type AccountInfo struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Country     string `json:"country,omitempty"`
	Affiliation string `json:"affiliation,omitempty"`
	Website     string `json:"website,omitempty"`
	MemberCount int    `json:"member_count,omitempty"`
	CaptainID   *int   `json:"captain_id,omitempty"`
}

func (s *Server) lookupAccount(ctx context.Context, _ *mcp.CallToolRequest, in LookupIn) (*mcp.CallToolResult, LookupOut, error) {
	var out LookupOut

	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind == "" {
		if s.detectMode(ctx, nil) == ctfd.ModeTeams {
			kind = "team"
		} else {
			kind = "user"
		}
	}
	if kind != "user" && kind != "team" {
		return nil, out, fmt.Errorf("invalid kind %q: use 'user' or 'team'", in.Kind)
	}
	out.Kind = kind

	if in.AccountID <= 0 && in.Search == "" {
		return nil, out, fmt.Errorf("provide either account_id or search")
	}

	if in.AccountID > 0 {
		info, err := s.fetchAccount(ctx, kind, in.AccountID)
		if err != nil {
			return nil, out, err
		}
		out.Matches = []AccountInfo{*info}

		if in.IncludeSolves {
			var solves []ctfd.Submission
			var serr error
			if kind == "team" {
				solves, serr = s.deps.Client.TeamSolvesByID(ctx, in.AccountID)
			} else {
				solves, serr = s.deps.Client.UserSolves(ctx, in.AccountID)
			}
			if serr != nil {
				s.log.Debug("could not read solves", "error", s.red.Error(serr))
			}
			for _, sv := range solves {
				e := SolveEntry{ChallengeID: sv.ChallengeID, Date: formatDate(sv.Date)}
				if sv.Challenge != nil {
					e.ChallengeName = sv.Challenge.Name
					e.Category = sv.Challenge.Category
					e.Value = sv.Challenge.Value
				}
				out.Solves = append(out.Solves, e)
			}
		}
		return textResult(renderLookup(out)), out, nil
	}

	filter := ctfd.AccountFilter{Q: in.Search, Field: "name"}
	if kind == "team" {
		teams, truncated, err := s.deps.Client.Teams(ctx, filter)
		if err != nil {
			return nil, out, err
		}
		out.Truncated = truncated
		for _, t := range teams {
			out.Matches = append(out.Matches, AccountInfo{
				ID: t.ID, Name: t.Name, Country: t.Country, Affiliation: t.Affiliation,
				Website: t.Website, MemberCount: len(t.Members), CaptainID: t.CaptainID,
			})
		}
	} else {
		users, truncated, err := s.deps.Client.Users(ctx, filter)
		if err != nil {
			return nil, out, err
		}
		out.Truncated = truncated
		for _, u := range users {
			out.Matches = append(out.Matches, AccountInfo{
				ID: u.ID, Name: u.Name, Country: u.Country,
				Affiliation: u.Affiliation, Website: u.Website,
			})
		}
	}
	return textResult(renderLookup(out)), out, nil
}

func (s *Server) fetchAccount(ctx context.Context, kind string, id int) (*AccountInfo, error) {
	if kind == "team" {
		t, err := s.deps.Client.Team(ctx, id)
		if err != nil {
			return nil, err
		}
		return &AccountInfo{
			ID: t.ID, Name: t.Name, Country: t.Country, Affiliation: t.Affiliation,
			Website: t.Website, MemberCount: len(t.Members), CaptainID: t.CaptainID,
		}, nil
	}
	u, err := s.deps.Client.User(ctx, id)
	if err != nil {
		return nil, err
	}
	return &AccountInfo{
		ID: u.ID, Name: u.Name, Country: u.Country,
		Affiliation: u.Affiliation, Website: u.Website,
	}, nil
}

func renderLookup(o LookupOut) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s lookup\n\n", strings.ToUpper(o.Kind[:1])+o.Kind[1:])
	if len(o.Matches) == 0 {
		b.WriteString("No matching accounts.\n")
		return b.String()
	}
	if o.Truncated {
		b.WriteString("Results were truncated at the configured page limit; narrow the search for a complete list.\n\n")
	}
	rows := make([][]string, 0, len(o.Matches))
	for _, m := range o.Matches {
		row := []string{itoa(m.ID), m.Name, m.Country, m.Affiliation}
		if o.Kind == "team" {
			row = append(row, itoa(m.MemberCount))
		}
		rows = append(rows, row)
	}
	headers := []string{"ID", "Name", "Country", "Affiliation"}
	if o.Kind == "team" {
		headers = append(headers, "Members")
	}
	b.WriteString(table(headers, rows))

	if len(o.Solves) > 0 {
		srows := make([][]string, 0, len(o.Solves))
		for _, sv := range o.Solves {
			srows = append(srows, []string{itoa(sv.ChallengeID), sv.ChallengeName, sv.Category, itoa(sv.Value), sv.Date})
		}
		section(&b, "Solves", table([]string{"ID", "Challenge", "Category", "Points", "Solved at"}, srows))
	}
	return b.String()
}
