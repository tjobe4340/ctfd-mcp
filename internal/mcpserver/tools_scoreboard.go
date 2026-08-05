package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// ScoreboardIn selects how much of the scoreboard to return.
type ScoreboardIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"How many top entries to return. Defaults to 25. Use 0 for the full scoreboard, which can be large."`
	// AroundMe reframes the window on the caller rather than the leaders,
	// which is what a competitor usually wants to know.
	AroundMe bool `json:"around_me,omitempty" jsonschema:"Center the window on your own position instead of showing the leaders."`
}

// ScoreboardOut is a scoreboard snapshot.
type ScoreboardOut struct {
	Mode        string          `json:"mode"`
	TotalRanked int             `json:"total_ranked"`
	Returned    int             `json:"returned"`
	MyRank      *int            `json:"my_rank,omitempty"`
	MyScore     *int            `json:"my_score,omitempty"`
	Entries     []ScoreboardRow `json:"entries"`
}

// ScoreboardRow is one ranked account.
type ScoreboardRow struct {
	Pos     int    `json:"pos"`
	ID      int    `json:"account_id"`
	Name    string `json:"name"`
	Score   int    `json:"score"`
	Bracket string `json:"bracket,omitempty"`
	IsMe    bool   `json:"is_me,omitempty"`
	Members int    `json:"members,omitempty"`
}

func (s *Server) registerScoreboardTools() {
	addTool(s, &mcp.Tool{
		Name:        "ctfd_scoreboard",
		Title:       "Scoreboard",
		Annotations: readOnly("Scoreboard"),
		Description: "Current standings. Use around_me=true to see your immediate competition rather than the leaders. " +
			"CTFd caches this server-side for 60 seconds, so polling faster than that returns identical data.",
	}, s.scoreboard)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_score_history",
		Title:       "Score history",
		Annotations: readOnly("Score history"),
		Description: "Scoring timelines for the top accounts: every solve and award with its timestamp and point value. " +
			"Use this to see which challenges the leaders solved and in what order, or to judge how fast the field is moving. " +
			"Entries with no challenge_id are point awards rather than solves.",
	}, s.scoreHistory)
}

func (s *Server) scoreboard(ctx context.Context, _ *mcp.CallToolRequest, in ScoreboardIn) (*mcp.CallToolResult, ScoreboardOut, error) {
	var out ScoreboardOut

	board, err := s.deps.Client.Scoreboard(ctx)
	if err != nil {
		// score_visibility=hidden answers 403; score_visibility=admins answers
		// 404 to mask the endpoint's existence. Both mean the same thing here.
		if ctfd.IsForbidden(err) || ctfd.IsNotFound(err) {
			return nil, out, fmt.Errorf("the scoreboard is hidden by the event organizers; " +
				"use ctfd_my_progress instead, which reads your own solves and is not affected by scoreboard visibility")
		}
		return nil, out, err
	}
	out.TotalRanked = len(board)
	if len(board) > 0 {
		out.Mode = board[0].AccountType
	}

	myAccountID := s.myAccountID(ctx)
	myIndex := -1
	for i, e := range board {
		if myAccountID > 0 && e.AccountID == myAccountID {
			myIndex = i
			pos, score := e.Pos, e.Score
			out.MyRank, out.MyScore = &pos, &score
			break
		}
	}

	limit := in.Limit
	if limit == 0 && !in.AroundMe {
		limit = 25
	}

	start, end := 0, len(board)
	switch {
	case in.AroundMe && myIndex >= 0:
		window := limit
		if window <= 0 {
			window = 10
		}
		start = max(0, myIndex-window/2)
		end = min(len(board), start+window)
		// Re-anchor so a caller near the bottom still gets a full window.
		start = max(0, end-window)
	case limit > 0 && limit < len(board):
		end = limit
	}

	for i := start; i < end; i++ {
		e := board[i]
		out.Entries = append(out.Entries, ScoreboardRow{
			Pos:     e.Pos,
			ID:      e.AccountID,
			Name:    e.Name,
			Score:   e.Score,
			Bracket: derefStr(e.BracketName),
			IsMe:    myAccountID > 0 && e.AccountID == myAccountID,
			Members: len(e.Members),
		})
	}
	out.Returned = len(out.Entries)

	return textResult(renderScoreboard(out, in)), out, nil
}

// myAccountID resolves the account ID that identifies the caller on the
// scoreboard: the team in team mode, the user otherwise. It returns 0 when it
// cannot be determined, which simply means no row gets highlighted.
func (s *Server) myAccountID(ctx context.Context) int {
	me, err := s.deps.Client.Me(ctx)
	if err != nil {
		return 0
	}
	if s.detectMode(ctx, me) == ctfd.ModeTeams && me.TeamID != nil {
		return *me.TeamID
	}
	return me.ID
}

func renderScoreboard(o ScoreboardOut, in ScoreboardIn) string {
	var b strings.Builder
	b.WriteString("# Scoreboard\n\n")
	fmt.Fprintf(&b, "%d ranked %s.\n", o.TotalRanked, plural(o.TotalRanked, "account", "accounts"))
	if o.MyRank != nil {
		fmt.Fprintf(&b, "You are rank %d with %d points.\n", *o.MyRank, derefInt(o.MyScore))
	} else {
		b.WriteString("Your account is not ranked yet.\n")
	}
	if o.Returned < o.TotalRanked {
		if in.AroundMe {
			fmt.Fprintf(&b, "\nShowing %d entries around your position.\n", o.Returned)
		} else {
			fmt.Fprintf(&b, "\nShowing the top %d.\n", o.Returned)
		}
	}
	b.WriteString("\n")

	rows := make([][]string, 0, len(o.Entries))
	showMembers := false
	for _, e := range o.Entries {
		if e.Members > 0 {
			showMembers = true
		}
	}
	for _, e := range o.Entries {
		name := e.Name
		if e.IsMe {
			name += "  <-- you"
		}
		row := []string{itoa(e.Pos), name, itoa(e.Score), e.Bracket}
		if showMembers {
			row = append(row, itoa(e.Members))
		}
		rows = append(rows, row)
	}
	headers := []string{"Rank", "Name", "Score", "Bracket"}
	if showMembers {
		headers = append(headers, "Members")
	}
	b.WriteString(table(headers, rows))
	return b.String()
}

// HistoryIn selects how many timelines to fetch.
type HistoryIn struct {
	Count int `json:"count,omitempty" jsonschema:"How many top accounts to include, 1 to 50. Defaults to 10."`
	// PerAccountLimit keeps a long event from returning thousands of events.
	PerAccountLimit int `json:"per_account_limit,omitempty" jsonschema:"Maximum scoring events to list per account, most recent last. Defaults to 25."`
}

// HistoryOut holds scoring timelines.
type HistoryOut struct {
	Accounts []AccountTimeline `json:"accounts"`
}

// AccountTimeline is one account's scoring events.
type AccountTimeline struct {
	Pos        int            `json:"pos"`
	AccountID  int            `json:"account_id"`
	Name       string         `json:"name"`
	Score      int            `json:"score"`
	EventCount int            `json:"event_count"`
	Events     []ScoringEvent `json:"events"`
}

// ScoringEvent is one solve or award on a timeline.
type ScoringEvent struct {
	ChallengeID *int   `json:"challenge_id,omitempty"`
	Value       int    `json:"value"`
	Date        string `json:"date"`
	IsAward     bool   `json:"is_award,omitempty"`
}

func (s *Server) scoreHistory(ctx context.Context, _ *mcp.CallToolRequest, in HistoryIn) (*mcp.CallToolResult, HistoryOut, error) {
	var out HistoryOut

	count := in.Count
	if count <= 0 {
		count = 10
	}
	perAccount := in.PerAccountLimit
	if perAccount <= 0 {
		perAccount = 25
	}

	entries, err := s.deps.Client.ScoreboardTop(ctx, count)
	if err != nil {
		// score_visibility=hidden answers 403; score_visibility=admins answers
		// 404 to mask the endpoint's existence. Both mean the same thing here.
		if ctfd.IsForbidden(err) || ctfd.IsNotFound(err) {
			return nil, out, fmt.Errorf("the scoreboard is hidden by the event organizers; " +
				"use ctfd_my_progress instead, which reads your own solves and is not affected by scoreboard visibility")
		}
		return nil, out, err
	}

	for _, e := range entries {
		t := AccountTimeline{
			Pos: e.Pos, AccountID: e.ID, Name: e.Name,
			Score: e.Score, EventCount: len(e.Solves),
		}
		// Keep the most recent events; the tail is what shows current momentum.
		start := 0
		if len(e.Solves) > perAccount {
			start = len(e.Solves) - perAccount
		}
		for _, sv := range e.Solves[start:] {
			t.Events = append(t.Events, ScoringEvent{
				ChallengeID: sv.ChallengeID,
				Value:       sv.Value,
				Date:        formatDate(sv.Date),
				IsAward:     sv.IsAward(),
			})
		}
		out.Accounts = append(out.Accounts, t)
	}

	var b strings.Builder
	b.WriteString("# Score history\n\n")
	if len(out.Accounts) == 0 {
		b.WriteString("No ranked accounts yet.\n")
		return textResult(b.String()), out, nil
	}
	for _, t := range out.Accounts {
		fmt.Fprintf(&b, "\n## %d. %s - %d points (%d scoring %s)\n\n",
			t.Pos, t.Name, t.Score, t.EventCount, plural(t.EventCount, "event", "events"))
		if len(t.Events) == 0 {
			b.WriteString("No scoring events.\n")
			continue
		}
		if t.EventCount > len(t.Events) {
			fmt.Fprintf(&b, "Showing the %d most recent.\n\n", len(t.Events))
		}
		rows := make([][]string, 0, len(t.Events))
		for _, ev := range t.Events {
			what := "award"
			if ev.ChallengeID != nil {
				what = "challenge " + itoa(*ev.ChallengeID)
			}
			rows = append(rows, []string{ev.Date, what, fmt.Sprintf("%+d", ev.Value)})
		}
		b.WriteString(table([]string{"When", "What", "Points"}, rows))
	}
	return textResult(b.String()), out, nil
}
