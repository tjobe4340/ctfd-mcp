package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// SubmitIn are the arguments to ctfd_submit_flag.
type SubmitIn struct {
	ChallengeID int    `json:"challenge_id" jsonschema:"The numeric challenge ID to submit against."`
	Flag        string `json:"flag" jsonschema:"The exact flag string. Do not guess, brute-force, or submit a partial answer: every wrong submission is recorded and may consume a limited attempt."`
	DryRun      bool   `json:"dry_run,omitempty" jsonschema:"When true, run every safety check and report what would happen without actually submitting. Use this to verify attempts remain before committing."`
	Force       bool   `json:"force,omitempty" jsonschema:"Override the refusal to resubmit a flag already tried this session, or to submit to an already-solved challenge. Only set this when the user has explicitly asked for it."`
}

// SubmitOut is the structured result of a submission.
type SubmitOut struct {
	ChallengeID int    `json:"challenge_id"`
	Submitted   bool   `json:"submitted"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	Correct     bool   `json:"correct"`
	// AttemptConsumed reports whether CTFd recorded a failed attempt.
	AttemptConsumed   bool `json:"attempt_consumed"`
	AttemptsRemaining *int `json:"attempts_remaining,omitempty"`
	// SessionSubmissions counts submissions this server has made for this
	// challenge.
	SessionSubmissions int `json:"session_submissions"`
}

func (s *Server) registerSubmitTools() {
	desc := "Submit a flag for a challenge. "
	if s.deps.AllowSubmit {
		desc += "SUBMISSION IS ENABLED AND IRREVERSIBLE. Each wrong flag is permanently recorded against your account, " +
			"may consume one of a limited number of attempts, and is visible to event organizers. " +
			"Submit only a flag you have actually derived from solving the challenge - never a guess, a pattern, or a brute-force candidate. " +
			"Use dry_run=true first to confirm attempts remain. This tool refuses a flag already tried this session."
	} else {
		desc += "SUBMISSION IS CURRENTLY DISABLED by server configuration, so this tool will not contact CTFd. " +
			"Report candidate flags to the user instead of calling this."
	}

	addTool(s, &mcp.Tool{
		Name:        "ctfd_submit_flag",
		Title:       "Submit a flag",
		Annotations: mutating("Submit a flag", false),
		Description: desc,
	}, s.submitFlag)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_session_report",
		Title:       "Session submission report",
		Annotations: readOnly("Session submission report"),
		Description: "Report what this server has submitted during the current session: which challenges were attempted, " +
			"how many submissions each received, and which succeeded. Flags themselves are stored hashed and never echoed back. " +
			"Use this to avoid repeating work after losing track.",
	}, s.sessionReport)
}

func (s *Server) submitFlag(ctx context.Context, _ *mcp.CallToolRequest, in SubmitIn) (*mcp.CallToolResult, SubmitOut, error) {
	out := SubmitOut{ChallengeID: in.ChallengeID}

	if in.ChallengeID <= 0 {
		return nil, out, fmt.Errorf("challenge_id must be a positive integer, got %d", in.ChallengeID)
	}
	flag := strings.TrimSpace(in.Flag)
	if flag == "" {
		return nil, out, fmt.Errorf("flag is empty; there is nothing to submit")
	}

	if !s.deps.AllowSubmit {
		out.Status = "disabled"
		return textResult(
			"Flag submission is disabled on this server, so nothing was submitted.\n\n" +
				"The candidate flag was not sent to CTFd. Report it to the user instead.\n\n" +
				"To enable submission, restart ctfd-mcp with CTFD_ALLOW_SUBMIT=true (or the -allow-submit flag). " +
				"This is deliberately off by default because submissions are irreversible and consume limited attempts.",
		), out, nil
	}

	// Refuse a repeat of a flag already tried. CTFd would happily record it as
	// another failure, spending an attempt on an answer already known wrong.
	if prior, ok := s.attempts.PriorAttempt(in.ChallengeID, flag); ok && !in.Force {
		out.Status = "duplicate"
		out.SessionSubmissions = s.attempts.Count(in.ChallengeID)
		return textResult(fmt.Sprintf(
			"Refused: this exact flag was already submitted for challenge %d during this session at %s, and the result was %q.\n\n"+
				"Resubmitting would consume another attempt for a known outcome. Derive a different flag, "+
				"or pass force=true if the user explicitly wants to retry.",
			in.ChallengeID, prior.at.Format("15:04:05"), prior.outcome,
		)), out, nil
	}

	if s.attempts.AlreadySolved(in.ChallengeID) && !in.Force {
		out.Status = "already_solved"
		out.Correct = true
		out.SessionSubmissions = s.attempts.Count(in.ChallengeID)
		return textResult(fmt.Sprintf(
			"Refused: challenge %d was already solved during this session. No submission was made.\n\n"+
				"Pass force=true only if you believe that record is wrong.", in.ChallengeID,
		)), out, nil
	}

	// Read the challenge first so the attempt budget can be checked before
	// anything irreversible happens. A failure here is not fatal: the CTF may
	// hide detail, and blocking a legitimate submission is worse than
	// submitting without the check.
	var remaining *int
	detail, detailErr := s.deps.Client.Challenge(ctx, in.ChallengeID)
	if detailErr != nil {
		s.log.Warn("could not read challenge before submitting",
			"challenge_id", in.ChallengeID, "error", s.red.Error(detailErr))
	} else {
		if detail.SolvedByMe && !in.Force {
			out.Status = string(ctfd.AttemptAlreadySolved)
			out.Correct = true
			return textResult(fmt.Sprintf(
				"Refused: CTFd reports challenge %d (%q) is already solved by your account. No submission was made.\n\n"+
					"Pass force=true to submit anyway.", in.ChallengeID, detail.Name,
			)), out, nil
		}
		if rem, capped := detail.AttemptsRemaining(); capped {
			remaining = &rem
			out.AttemptsRemaining = &rem
			if rem == 0 && !in.Force {
				out.Status = "no_attempts_remaining"
				return textResult(fmt.Sprintf(
					"Refused: challenge %d (%q) allows %d attempts and CTFd reports %d used. No submission was made.\n\n"+
						"CTFd would reject this while still logging it.\n\n"+
						"Note: this count comes from CTFd's `attempts` field, which counts all submissions, "+
						"while the limit is enforced against failed submissions only. If you believe an attempt "+
						"is actually left, pass force=true.",
					in.ChallengeID, detail.Name, detail.MaxAttempts, detail.Attempts,
				)), out, nil
			}
		}
	}

	if in.DryRun {
		out.Status = "dry_run"
		var b strings.Builder
		fmt.Fprintf(&b, "Dry run: nothing was submitted to CTFd.\n\nAll checks passed for challenge %d", in.ChallengeID)
		if detail != nil {
			fmt.Fprintf(&b, " (%q)", detail.Name)
		}
		b.WriteString(".\n")
		if remaining != nil {
			fmt.Fprintf(&b, "Attempts remaining: %d. A real submission would leave %d.\n", *remaining, *remaining-1)
		} else {
			b.WriteString("This challenge has no attempt limit.\n")
		}
		b.WriteString("\nCall again with dry_run omitted to submit for real.")
		return textResult(b.String()), out, nil
	}

	res, err := s.deps.Client.Attempt(ctx, in.ChallengeID, flag)
	if err != nil {
		// The submission may or may not have been recorded, so log the attempt
		// either way rather than risking a duplicate on the next call.
		s.attempts.Record(in.ChallengeID, flag, "error")
		return nil, out, err
	}

	s.attempts.Record(in.ChallengeID, flag, string(res.Status))
	out.Submitted = true
	out.Status = string(res.Status)
	out.Message = res.Message
	out.Correct = res.Status == ctfd.AttemptCorrect
	out.AttemptConsumed = res.ConsumedAttempt()
	out.SessionSubmissions = s.attempts.Count(in.ChallengeID)
	if remaining != nil && out.AttemptConsumed {
		left := *remaining - 1
		if left < 0 {
			left = 0
		}
		out.AttemptsRemaining = &left
	}

	s.log.Info("flag submitted",
		"challenge_id", in.ChallengeID,
		"status", string(res.Status),
		"http_status", res.HTTPStatus,
	)

	return textResult(renderSubmission(in.ChallengeID, detail, res, out)), out, nil
}

func renderSubmission(id int, detail *ctfd.ChallengeDetail, res *ctfd.AttemptResult, out SubmitOut) string {
	name := ""
	if detail != nil {
		name = fmt.Sprintf(" (%q)", detail.Name)
	}

	var b strings.Builder
	switch res.Status {
	case ctfd.AttemptCorrect:
		fmt.Fprintf(&b, "CORRECT. Challenge %d%s is solved.\n", id, name)
		if detail != nil && detail.Value > 0 {
			fmt.Fprintf(&b, "Awarded %d points.\n", detail.Value)
		}
		if detail != nil && detail.NextID != nil {
			fmt.Fprintf(&b, "The organizers suggest challenge %d next.\n", *detail.NextID)
		}

	case ctfd.AttemptIncorrect:
		fmt.Fprintf(&b, "INCORRECT. The flag was rejected for challenge %d%s, and a failed attempt has been recorded.\n", id, name)
		if out.AttemptsRemaining != nil {
			fmt.Fprintf(&b, "Attempts remaining: %d.\n", *out.AttemptsRemaining)
			if *out.AttemptsRemaining == 0 {
				b.WriteString("No attempts remain. Do not submit again for this challenge.\n")
			} else if *out.AttemptsRemaining <= 2 {
				b.WriteString("Very few attempts remain. Do not submit another candidate without new evidence.\n")
			}
		}
		b.WriteString("\nRe-examine the challenge rather than trying a variation of the same string. " +
			"Common causes: wrong flag format wrapper, trailing whitespace, or an incomplete decode.\n")

	case ctfd.AttemptAlreadySolved:
		fmt.Fprintf(&b, "ALREADY SOLVED. Challenge %d%s was already credited to your account; no attempt was consumed.\n", id, name)

	case ctfd.AttemptPaused:
		fmt.Fprintf(&b, "NOT SUBMITTED. The competition is paused, so CTFd did not evaluate the flag for challenge %d.\n", id)
		b.WriteString("Wait for the organizers to resume the event, then submit again.\n")

	case ctfd.AttemptRateLimited:
		fmt.Fprintf(&b, "RATE LIMITED. CTFd rejected the submission for challenge %d because too many wrong flags were sent in the last minute.\n", id)
		b.WriteString("\nImportant: CTFd records a failed attempt even for a rate-limited submission, " +
			"so this cost an attempt without the flag being evaluated. " +
			"Wait at least a minute before submitting anything else, and stop submitting speculative flags.\n")

	case ctfd.AttemptAuthRequired:
		fmt.Fprintf(&b, "NOT SUBMITTED. CTFd rejected the request as unauthenticated.\n")
		b.WriteString("Check that CTFD_TOKEN is valid and has not been revoked.\n")

	default:
		fmt.Fprintf(&b, "Submission for challenge %d returned status %q.\n", id, res.Status)
	}

	if res.Message != "" {
		b.WriteString("\n" + untrusted("CTFd response message", res.Message))
	}
	return b.String()
}

// SessionReportOut summarizes this session's submission activity.
type SessionReportOut struct {
	TotalSubmissions    int  `json:"total_submissions"`
	ChallengesAttempted int  `json:"challenges_attempted"`
	ChallengesSolved    int  `json:"challenges_solved"`
	SubmitEnabled       bool `json:"submit_enabled"`
}

func (s *Server) sessionReport(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, SessionReportOut, error) {
	subs, challenges, solved := s.attempts.Summary()
	out := SessionReportOut{
		TotalSubmissions:    subs,
		ChallengesAttempted: challenges,
		ChallengesSolved:    solved,
		SubmitEnabled:       s.deps.AllowSubmit,
	}

	var b strings.Builder
	b.WriteString("# Session submission report\n\n")
	if !out.SubmitEnabled {
		b.WriteString("Flag submission is disabled on this server.\n\n")
	}
	if subs == 0 {
		b.WriteString("No flags have been submitted through this server during this session.\n")
		b.WriteString("\nNote: this only covers submissions made by this process. Solves recorded by CTFd " +
			"from the web UI or an earlier session are not counted here; use ctfd_my_progress for the authoritative record.\n")
		return textResult(b.String()), out, nil
	}
	fmt.Fprintf(&b, "- Submissions made: %d\n", subs)
	fmt.Fprintf(&b, "- Challenges attempted: %d\n", challenges)
	fmt.Fprintf(&b, "- Challenges solved: %d\n", solved)
	b.WriteString("\nThis covers only submissions made by this process. " +
		"Use ctfd_my_progress for the authoritative record from CTFd.\n")
	return textResult(b.String()), out, nil
}
