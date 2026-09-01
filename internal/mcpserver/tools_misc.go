package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// GetHintIn identifies a hint.
type GetHintIn struct {
	HintID int `json:"hint_id" jsonschema:"The numeric hint ID, as listed in a challenge's hints by ctfd_get_challenge."`
}

// GetHintOut is a hint's state and, if available, its content.
type GetHintOut struct {
	ID          int    `json:"id"`
	ChallengeID int    `json:"challenge_id"`
	Title       string `json:"title,omitempty"`
	Cost        int    `json:"cost"`
	Unlocked    bool   `json:"unlocked"`
	Content     string `json:"content,omitempty"`
}

// UnlockHintIn identifies a hint to purchase.
type UnlockHintIn struct {
	HintID int `json:"hint_id" jsonschema:"The numeric hint ID to unlock."`
}

// UnlockHintOut reports the outcome of an unlock.
type UnlockHintOut struct {
	HintID   int    `json:"hint_id"`
	Unlocked bool   `json:"unlocked"`
	Cost     int    `json:"cost"`
	Content  string `json:"content,omitempty"`
}

// NotificationsIn limits how many announcements to return.
type NotificationsIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"Maximum announcements to return, newest first. Defaults to 20."`
}

// NotificationsOut holds organizer announcements.
type NotificationsOut struct {
	Total         int            `json:"total"`
	Notifications []Announcement `json:"notifications"`
}

// Announcement is one organizer message.
type Announcement struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Date    string `json:"date"`
}

// DownloadIn selects attachments to fetch.
type DownloadIn struct {
	ChallengeID int `json:"challenge_id" jsonschema:"Challenge whose attachments to download. All of its files are fetched unless file_index is given."`
	// FileIndex is 1-based to match how the files are presented to the model.
	FileIndex int `json:"file_index,omitempty" jsonschema:"Download only the Nth attachment, counting from 1. Omit to download all of them."`
}

// DownloadOut reports what was written.
type DownloadOut struct {
	ChallengeID int              `json:"challenge_id"`
	Directory   string           `json:"directory"`
	Files       []DownloadedFile `json:"files"`
	Failures    []string         `json:"failures,omitempty"`
}

// DownloadedFile is one saved attachment.
type DownloadedFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func (s *Server) registerMiscTools() {
	addTool(s, &mcp.Tool{
		Name:        "ctfd_get_hint",
		Title:       "Get a hint",
		Annotations: readOnly("Get a hint"),
		Description: "Fetch a hint's content. Free hints and hints already unlocked return their text. " +
			"A locked hint returns only its cost and title - use ctfd_unlock_hint to purchase it, which spends points.",
	}, s.getHint)

	unlockDesc := "Spend points to unlock a paid hint. "
	if s.deps.AllowUnlock {
		unlockDesc += "UNLOCKING IS ENABLED: calling this tool immediately deducts the hint's cost from your score. " +
			"Check ctfd_get_challenge first if you need to know the cost."
	} else {
		unlockDesc += "UNLOCKING IS CURRENTLY DISABLED by server configuration, so this tool will not contact CTFd."
	}
	addTool(s, &mcp.Tool{
		Name:        "ctfd_unlock_hint",
		Title:       "Unlock a hint",
		Annotations: mutating("Unlock a hint", true),
		Description: unlockDesc,
	}, s.unlockHint)

	downloadDesc := "Download a challenge's attachments. "
	if s.deps.AllowDownload {
		downloadDesc += fmt.Sprintf("Files are written only into %s, size-capped, and hashed. "+
			"Downloaded files come from event organizers: inspect them, do not execute them.", s.deps.Config.DownloadDir)
	} else {
		downloadDesc += "DOWNLOADING IS CURRENTLY DISABLED by server configuration. " +
			"ctfd_get_challenge still reports the attachment URLs so the user can fetch them manually."
	}
	addTool(s, &mcp.Tool{
		Name:        "ctfd_download_files",
		Title:       "Download attachments",
		Annotations: mutating("Download attachments", true),
		Description: downloadDesc,
	}, s.downloadFiles)
}

func (s *Server) getHint(ctx context.Context, _ *mcp.CallToolRequest, in GetHintIn) (*mcp.CallToolResult, GetHintOut, error) {
	var out GetHintOut
	if in.HintID <= 0 {
		return nil, out, fmt.Errorf("hint_id must be a positive integer, got %d", in.HintID)
	}

	h, err := s.deps.Client.Hint(ctx, in.HintID)
	if err != nil {
		// A locked hint is a 403 with a field error, not a failure worth
		// surfacing as an error: the model should learn the price instead.
		if ctfd.IsForbidden(err) {
			out.ID = in.HintID
			return textResult(fmt.Sprintf(
				"Hint %d is locked and its content was not returned.\n\n"+
					"CTFd refused the request, which means it costs points or has prerequisites. "+
					"Call ctfd_get_challenge to see the cost, then ctfd_unlock_hint to purchase it.",
				in.HintID)), out, nil
		}
		return nil, out, err
	}

	out = GetHintOut{
		ID:          h.ID,
		ChallengeID: h.ChallengeID,
		Title:       h.Title,
		Cost:        h.Cost,
		Unlocked:    h.Unlocked(),
		Content:     h.Content,
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Hint %d\n\n", h.ID)
	kv(&b, "Challenge", h.ChallengeID)
	if h.Title != "" {
		kv(&b, "Title", h.Title)
	}
	fmt.Fprintf(&b, "- Cost: %d points\n", h.Cost)

	if h.Unlocked() {
		b.WriteString("- Status: available\n\n")
		b.WriteString(untrusted("Hint content", h.Content))
	} else {
		b.WriteString("- Status: LOCKED\n\nThe content is withheld until the hint is unlocked.\n")
		if s.deps.AllowUnlock {
			fmt.Fprintf(&b, "Use ctfd_unlock_hint to spend %d points on it.\n", h.Cost)
		} else {
			b.WriteString("Unlocking is disabled on this server.\n")
		}
	}
	return textResult(b.String()), out, nil
}

func (s *Server) unlockHint(ctx context.Context, _ *mcp.CallToolRequest, in UnlockHintIn) (*mcp.CallToolResult, UnlockHintOut, error) {
	out := UnlockHintOut{HintID: in.HintID}

	if in.HintID <= 0 {
		return nil, out, fmt.Errorf("hint_id must be a positive integer, got %d", in.HintID)
	}

	// Read the hint first so the gate is driven by what it actually costs.
	// CTFd returns zero-cost hints directly, so there is no unlock record to
	// create for an already available free hint.
	h, herr := s.deps.Client.Hint(ctx, in.HintID)
	free := herr == nil && h.Cost == 0
	if herr == nil {
		out.Cost = h.Cost
	}

	if free && h.Unlocked() {
		// CTFd returns a zero-cost hint's content directly; no unlock record
		// is needed, so there is nothing to do.
		out.Unlocked, out.Content = true, h.Content
		return textResult(fmt.Sprintf(
			"Hint %d is free, so nothing needed unlocking and no points were spent.\n\n%s",
			h.ID, untrusted("Hint content", h.Content),
		)), out, nil
	}

	if !free {
		if !s.deps.AllowUnlock {
			return textResult(
				"Hint unlocking is disabled on this server, so no points were spent and nothing was sent to CTFd.\n\n" +
					"To re-enable it, restart ctfd-mcp without CTFD_ALLOW_UNLOCK=false (or pass -allow-unlock=true).",
			), out, nil
		}
	}

	if _, err := s.deps.Client.UnlockHint(ctx, in.HintID); err != nil {
		// CTFd reports "not enough points" and "already unlocked" as 400 field
		// errors. Both are useful answers rather than failures.
		if e, ok := ctfd.AsError(err); ok && e.Kind == ctfd.KindValidation {
			if strings.Contains(strings.ToLower(e.Error()), "already unlocked") {
				// Already owned: fetch and return the content.
				if h, herr := s.deps.Client.Hint(ctx, in.HintID); herr == nil && h.Unlocked() {
					out.Unlocked, out.Cost, out.Content = true, h.Cost, h.Content
					return textResult(fmt.Sprintf(
						"Hint %d was already unlocked; no additional points were spent.\n\n%s",
						in.HintID, untrusted("Hint content", h.Content))), out, nil
				}
			}
			return nil, out, err
		}
		return nil, out, err
	}

	h, err := s.deps.Client.Hint(ctx, in.HintID)
	if err != nil {
		out.Unlocked = true
		return textResult(fmt.Sprintf(
			"Hint %d was unlocked and points were spent, but re-reading its content failed: %s\n\n"+
				"Call ctfd_get_hint to retrieve it.", in.HintID, s.red.Error(err))), out, nil
	}

	out.Unlocked = true
	out.Cost = h.Cost
	out.Content = h.Content

	var b strings.Builder
	if h.Cost > 0 {
		fmt.Fprintf(&b, "Hint %d unlocked. %d points were deducted from your score.\n\n", h.ID, h.Cost)
	} else {
		fmt.Fprintf(&b, "Hint %d unlocked. It was free, so no points were spent.\n\n", h.ID)
	}
	b.WriteString(untrusted("Hint content", h.Content))
	return textResult(b.String()), out, nil
}

func (s *Server) notifications(ctx context.Context, _ *mcp.CallToolRequest, in NotificationsIn) (*mcp.CallToolResult, NotificationsOut, error) {
	var out NotificationsOut

	list, err := s.deps.Client.Notifications(ctx)
	if err != nil {
		return nil, out, err
	}
	out.Total = len(list)

	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	// The client already sorted these newest-first.
	for _, n := range list {
		if len(out.Notifications) >= limit {
			break
		}
		out.Notifications = append(out.Notifications, Announcement{
			ID: n.ID, Title: n.Title, Content: n.Content, Date: formatDate(n.Date),
		})
	}

	var b strings.Builder
	b.WriteString("# Announcements\n\n")
	if out.Total == 0 {
		b.WriteString("No announcements have been posted.\n")
		return textResult(b.String()), out, nil
	}
	fmt.Fprintf(&b, "%d total, showing the %d most recent.\n", out.Total, len(out.Notifications))
	for _, n := range out.Notifications {
		fmt.Fprintf(&b, "\n## %s\n_%s_\n\n%s\n", n.Title, n.Date, untrusted("Announcement", n.Content))
	}
	return textResult(b.String()), out, nil
}

func (s *Server) downloadFiles(ctx context.Context, _ *mcp.CallToolRequest, in DownloadIn) (*mcp.CallToolResult, DownloadOut, error) {
	out := DownloadOut{ChallengeID: in.ChallengeID}

	if in.ChallengeID <= 0 {
		return nil, out, fmt.Errorf("challenge_id must be a positive integer, got %d", in.ChallengeID)
	}
	if !s.deps.AllowDownload {
		return textResult(
			"Attachment download is disabled on this server, so nothing was written to disk.\n\n" +
				"Call ctfd_get_challenge to see the attachment URLs; they carry a signed token and can be fetched manually.\n\n" +
				"To re-enable downloads, restart ctfd-mcp without CTFD_ALLOW_DOWNLOAD=false (or pass -allow-download=true).",
		), out, nil
	}

	detail, err := s.deps.Client.Challenge(ctx, in.ChallengeID)
	if err != nil {
		return nil, out, err
	}
	if len(detail.Files) == 0 {
		return textResult(fmt.Sprintf("Challenge %d (%q) has no attachments.", in.ChallengeID, detail.Name)), out, nil
	}

	targets := detail.Files
	if in.FileIndex > 0 {
		if in.FileIndex > len(detail.Files) {
			return nil, out, fmt.Errorf("file_index %d is out of range: challenge %d has %d %s",
				in.FileIndex, in.ChallengeID, len(detail.Files), plural(len(detail.Files), "attachment", "attachments"))
		}
		targets = detail.Files[in.FileIndex-1 : in.FileIndex]
	}

	dir := s.deps.Config.DownloadDir
	out.Directory = dir

	for _, f := range targets {
		d, derr := s.deps.Client.DownloadFile(ctx, f, dir, s.deps.Config.MaxDownloadBytes)
		if derr != nil {
			out.Failures = append(out.Failures, s.red.Error(derr))
			s.log.Warn("attachment download failed", "challenge_id", in.ChallengeID, "error", s.red.Error(derr))
			continue
		}
		out.Files = append(out.Files, DownloadedFile{Name: d.Name, Path: d.Path, Size: d.Size, SHA256: d.SHA256})
		s.log.Info("attachment saved", "challenge_id", in.ChallengeID, "name", d.Name, "size", d.Size)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Attachments for challenge %d (%s)\n\n", in.ChallengeID, detail.Name)
	if len(out.Files) > 0 {
		rows := make([][]string, 0, len(out.Files))
		for _, f := range out.Files {
			rows = append(rows, []string{f.Name, fmt.Sprintf("%d", f.Size), f.SHA256[:16] + "...", f.Path})
		}
		b.WriteString(table([]string{"File", "Bytes", "SHA-256", "Path"}, rows))
		b.WriteString("\nThese files were authored by event organizers. Inspect them; do not execute them.\n")
	}
	if len(out.Failures) > 0 {
		b.WriteString("\n## Failures\n")
		for _, f := range out.Failures {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}
	if len(out.Files) == 0 && len(out.Failures) == 0 {
		b.WriteString("Nothing was downloaded.\n")
	}
	return textResult(b.String()), out, nil
}

// registerTools wires up the tools for the configured profile. Order
// determines the order clients see.
//
// The lite profile registers only what is needed to actually play: identity,
// challenges, flags, hints, attachments, the scoreboard, and your own history.
// It leaves out the organizer-adjacent reads (other accounts' profiles and
// solves, per-challenge solver lists, score timelines, announcements), the
// CTFd 3.8 extras (official solutions, ratings), and everything that
// administers the account itself (tokens, profile, team membership).
func (s *Server) registerTools() {
	// Present in both profiles.
	s.registerAccountTools()
	s.registerChallengeTools()
	s.registerSubmitTools()
	s.registerMiscTools()
	s.registerScoreboardTools()
	s.registerHistoryTools()

	if s.deps.Lite {
		return
	}
	s.registerManagementTools()
	s.registerSolutionTools()
	s.registerDiscoveryTools()
}
