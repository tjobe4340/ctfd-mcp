package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// These tools cover features CTFd added in 3.8. On 3.7 the routes do not exist
// and answer 404, which is reported as "this instance does not support it"
// rather than as a missing challenge.

// GetSolutionIn identifies a challenge whose official solution to read.
type GetSolutionIn struct {
	ChallengeID int `json:"challenge_id" jsonschema:"The numeric challenge ID."`
	// Unlock is opt-in because CTFd records who read a solution, even though
	// it charges nothing for it.
	Unlock bool `json:"unlock,omitempty" jsonschema:"Reveal the solution if it is gated. Unlocking a solution costs no points, but CTFd records that you viewed it. Defaults to false."`
}

// GetSolutionOut is an official solution, if readable.
type GetSolutionOut struct {
	ChallengeID int    `json:"challenge_id"`
	Available   bool   `json:"available"`
	State       string `json:"state,omitempty"`
	SolutionID  *int   `json:"solution_id,omitempty"`
	Content     string `json:"content,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// RateChallengeIn records a rating.
type RateChallengeIn struct {
	ChallengeID int `json:"challenge_id" jsonschema:"The numeric challenge ID. You must have solved it already."`
	// Rating is constrained to CTFd's two allowed values.
	Rating string `json:"rating" jsonschema:"Either 'up' or 'down'. CTFd only supports a thumbs up or down, not a scale."`
	Review string `json:"review,omitempty" jsonschema:"Optional written feedback for the organizers, up to 2000 characters."`
}

// RateChallengeOut confirms a rating.
type RateChallengeOut struct {
	ChallengeID int    `json:"challenge_id"`
	Rating      string `json:"rating"`
	Review      string `json:"review,omitempty"`
}

// MySubmissionsIn optionally narrows to one challenge.
type MySubmissionsIn struct {
	ChallengeID int `json:"challenge_id,omitempty" jsonschema:"Only return submissions for this challenge. Omit for all of them."`
}

// MySubmissionsOut lists this account's own submissions.
type MySubmissionsOut struct {
	Count       int              `json:"count"`
	Submissions []OwnSubmissionO `json:"submissions"`
}

// OwnSubmissionO is one submission, including what was typed.
type OwnSubmissionO struct {
	ChallengeID int    `json:"challenge_id"`
	Provided    string `json:"provided"`
	Correct     bool   `json:"correct"`
	Date        string `json:"date,omitempty"`
}

func (s *Server) registerSolutionTools() {
	addTool(s, &mcp.Tool{
		Name:        "ctfd_get_solution",
		Title:       "Get official solution",
		Annotations: mutating("Get official solution", true),
		Description: "Read the organizers' official solution or writeup for a challenge, when one has been published. " +
			"Most solutions unlock only after you have solved the challenge yourself. " +
			"Unlocking costs no points, but CTFd records that you viewed it, so it is opt-in via unlock=true. " +
			"Requires CTFd 3.8 or newer.",
	}, s.getSolution)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_rate_challenge",
		Title:       "Rate a challenge",
		Annotations: mutating("Rate a challenge", true),
		Description: "Give a challenge a thumbs up or down, with optional written feedback for the organizers. " +
			"CTFd requires that you have already solved the challenge. Rating again replaces your previous rating rather than adding one. " +
			"Requires CTFd 3.8 or newer, and the organizers must have ratings enabled.",
	}, s.rateChallenge)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_my_submissions",
		Title:       "My raw submissions",
		Annotations: readOnly("My raw submissions"),
		Description: "Your own submission history including the exact strings you submitted, which ctfd_my_progress does not show. " +
			"Useful for seeing precisely what was already tried on a challenge. " +
			"Many events leave this disabled, in which case it reports that rather than failing.",
	}, s.mySubmissions)
}

func (s *Server) getSolution(ctx context.Context, _ *mcp.CallToolRequest, in GetSolutionIn) (*mcp.CallToolResult, GetSolutionOut, error) {
	out := GetSolutionOut{ChallengeID: in.ChallengeID}
	if in.ChallengeID <= 0 {
		return nil, out, fmt.Errorf("challenge_id must be a positive integer, got %d", in.ChallengeID)
	}

	ref, err := s.deps.Client.ChallengeSolution(ctx, in.ChallengeID)
	if err != nil {
		if ctfd.IsNotFound(err) {
			// Ambiguous on purpose: CTFd 3.7 has no such route, and 3.8
			// answers 404 for a challenge that does not exist.
			return textResult(fmt.Sprintf(
				"No solution is available for challenge %d.\n\n"+
					"Either this CTFd instance predates 3.8 (which added official solutions), "+
					"or that challenge does not exist.", in.ChallengeID,
			)), out, nil
		}
		return nil, out, err
	}
	out.State = ref.State
	out.SolutionID = ref.ID
	out.Available = ref.Available()

	if !ref.Available() {
		// Whether the challenge is solved changes the explanation, and it is
		// worth one extra read to get that right.
		solvedByMe := false
		if d, derr := s.deps.Client.Challenge(ctx, in.ChallengeID); derr == nil {
			solvedByMe = d.SolvedByMe
		}
		out.Reason = ref.Explain(solvedByMe)
		return textResult(fmt.Sprintf("# Solution for challenge %d\n\n%s", in.ChallengeID, out.Reason)), out, nil
	}

	sol, err := s.deps.Client.Solution(ctx, *ref.ID)
	if err != nil {
		return nil, out, err
	}

	if !sol.Unlocked() {
		if !in.Unlock {
			out.Reason = "The solution is published but not yet revealed for your account."
			return textResult(fmt.Sprintf(
				"# Solution for challenge %d\n\n"+
					"A solution exists (ID %d) but has not been revealed for your account.\n\n"+
					"Revealing it costs no points, but CTFd records that you viewed it. "+
					"Call again with unlock=true to read it.", in.ChallengeID, sol.ID,
			)), out, nil
		}
		if _, uerr := s.deps.Client.UnlockSolution(ctx, sol.ID); uerr != nil {
			// Already unlocked is reported as a 400 field error; re-reading is
			// the right response rather than surfacing it as a failure.
			if !ctfd.IsAlreadyUnlocked(uerr) {
				return nil, out, uerr
			}
		}
		sol, err = s.deps.Client.Solution(ctx, *ref.ID)
		if err != nil {
			return nil, out, err
		}
	}

	body := sol.Content
	if body == "" {
		body = sol.HTML
	}
	out.Content = body

	var b strings.Builder
	fmt.Fprintf(&b, "# Official solution for challenge %d\n\n", in.ChallengeID)
	if body == "" {
		b.WriteString("CTFd reported the solution as readable but returned no content.\n")
		return textResult(b.String()), out, nil
	}
	b.WriteString(untrusted("Official solution", body))
	return textResult(b.String()), out, nil
}

func (s *Server) rateChallenge(ctx context.Context, _ *mcp.CallToolRequest, in RateChallengeIn) (*mcp.CallToolResult, RateChallengeOut, error) {
	out := RateChallengeOut{ChallengeID: in.ChallengeID}
	if in.ChallengeID <= 0 {
		return nil, out, fmt.Errorf("challenge_id must be a positive integer, got %d", in.ChallengeID)
	}

	var value int
	switch strings.ToLower(strings.TrimSpace(in.Rating)) {
	case "up", "+1", "1", "good", "positive":
		value = 1
	case "down", "-1", "bad", "negative":
		value = -1
	default:
		return nil, out, fmt.Errorf("rating must be 'up' or 'down', got %q", in.Rating)
	}
	if len(in.Review) > 2000 {
		return nil, out, fmt.Errorf("review is %d characters; CTFd allows at most 2000", len(in.Review))
	}

	if _, err := s.deps.Client.RateChallenge(ctx, in.ChallengeID, value, in.Review); err != nil {
		switch {
		case ctfd.IsNotFound(err):
			return textResult(fmt.Sprintf(
				"Could not rate challenge %d.\n\n"+
					"Either this CTFd instance predates 3.8 (which added challenge ratings), "+
					"or that challenge does not exist.", in.ChallengeID,
			)), out, nil
		case ctfd.IsForbidden(err):
			return textResult(fmt.Sprintf(
				"Could not rate challenge %d.\n\n"+
					"CTFd requires that you solve a challenge before rating it, and organizers can disable "+
					"ratings entirely. Both cases are reported this way.", in.ChallengeID,
			)), out, nil
		}
		return nil, out, err
	}

	out.Rating = strings.ToLower(strings.TrimSpace(in.Rating))
	out.Review = in.Review

	verdict := "thumbs up"
	if value == -1 {
		verdict = "thumbs down"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Rated challenge %d: %s.\n", in.ChallengeID, verdict)
	if in.Review != "" {
		fmt.Fprintf(&b, "\nYour review was recorded (%d characters).\n", len(in.Review))
	}
	b.WriteString("\nRating again replaces this rather than adding another.\n")
	return textResult(b.String()), out, nil
}

func (s *Server) mySubmissions(ctx context.Context, _ *mcp.CallToolRequest, in MySubmissionsIn) (*mcp.CallToolResult, MySubmissionsOut, error) {
	var out MySubmissionsOut

	subs, err := s.deps.Client.MySubmissions(ctx, in.ChallengeID)
	if err != nil {
		switch {
		case ctfd.IsForbidden(err):
			return textResult(
				"This event does not let players view their own raw submissions.\n\n" +
					"CTFd keeps that behind the view_self_submissions setting, which is off by default. " +
					"Use ctfd_my_progress for solves and awards, or ctfd_session_report for what this session submitted.",
			), out, nil
		case ctfd.IsNotFound(err):
			return textResult(
				"This CTFd instance does not expose per-player submission history; it predates CTFd 3.8.\n\n" +
					"Use ctfd_my_progress instead.",
			), out, nil
		}
		return nil, out, err
	}

	for _, sub := range subs {
		out.Submissions = append(out.Submissions, OwnSubmissionO{
			ChallengeID: sub.ChallengeID,
			Provided:    sub.Provided,
			Correct:     sub.Correct(),
			Date:        formatDate(sub.Date),
		})
	}
	out.Count = len(out.Submissions)

	var b strings.Builder
	b.WriteString("# My submissions\n\n")
	if out.Count == 0 {
		b.WriteString("No submissions recorded.\n")
		return textResult(b.String()), out, nil
	}
	fmt.Fprintf(&b, "%d %s.\n\n", out.Count, plural(out.Count, "submission", "submissions"))
	rows := make([][]string, 0, len(out.Submissions))
	for _, sub := range out.Submissions {
		verdict := "wrong"
		if sub.Correct {
			verdict = "CORRECT"
		}
		rows = append(rows, []string{itoa(sub.ChallengeID), sub.Provided, verdict, sub.Date})
	}
	b.WriteString(table([]string{"Challenge", "Submitted", "Result", "When"}, rows))
	return textResult(b.String()), out, nil
}
