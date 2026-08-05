package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tjobe4340/ctfd-mcp/internal/ctfd"
)

// TokenInfo is one API token belonging to the current user. The plaintext
// value is never included here; it exists only on creation.
type TokenInfo struct {
	ID          int    `json:"id"`
	Description string `json:"description,omitempty"`
	Created     string `json:"created,omitempty"`
	Expiration  string `json:"expiration,omitempty"`
	Expired     bool   `json:"expired,omitempty"`
}

// ListTokensOut lists the current user's API tokens.
type ListTokensOut struct {
	Count  int         `json:"count"`
	Tokens []TokenInfo `json:"tokens"`
}

// CreateTokenIn describes a token to mint.
type CreateTokenIn struct {
	Description string `json:"description,omitempty" jsonschema:"A note recording what this token is for, e.g. \"ctfd-mcp on laptop\"."`
	Expiration  string `json:"expiration,omitempty" jsonschema:"Expiry date as YYYY-MM-DD. Defaults to CTFd's own policy, normally 30 days."`
	Confirm     bool   `json:"confirm,omitempty" jsonschema:"Must be set to true to proceed. A new token is a long-lived credential for your account; ask the user before creating one."`
}

// CreateTokenOut reports a newly minted token.
type CreateTokenOut struct {
	ID          int    `json:"id"`
	Description string `json:"description,omitempty"`
	Expiration  string `json:"expiration,omitempty"`
	// Value is the plaintext token. CTFd shows it exactly once.
	Value string `json:"value"`
}

// RevokeTokenIn identifies a token to delete.
type RevokeTokenIn struct {
	TokenID int  `json:"token_id" jsonschema:"The numeric token ID from ctfd_list_tokens."`
	Confirm bool `json:"confirm,omitempty" jsonschema:"Must be set to true to proceed. Revoking is immediate and irreversible, and will break anything still using the token."`
}

// UpdateProfileIn holds profile changes. Every field is optional; omitted
// fields are left untouched.
type UpdateProfileIn struct {
	Name        string `json:"name,omitempty" jsonschema:"New display name. This is what appears on the scoreboard."`
	Email       string `json:"email,omitempty" jsonschema:"New email address. Requires current_password, and may trigger re-verification."`
	Website     string `json:"website,omitempty" jsonschema:"Profile website URL."`
	Affiliation string `json:"affiliation,omitempty" jsonschema:"Affiliation, such as a school or company."`
	Country     string `json:"country,omitempty" jsonschema:"Two-letter country code, e.g. US."`
	NewPassword string `json:"new_password,omitempty" jsonschema:"New password. Requires current_password."`
	// CurrentPassword is what CTFd calls "confirm".
	CurrentPassword string `json:"current_password,omitempty" jsonschema:"Your current password. CTFd requires it to change the password or email."`
}

// ProfileOut is a profile after update.
type ProfileOut struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email,omitempty"`
	Website     string `json:"website,omitempty"`
	Affiliation string `json:"affiliation,omitempty"`
	Country     string `json:"country,omitempty"`
}

// TeamActionIn joins or creates a team.
type TeamActionIn struct {
	Action   string `json:"action" jsonschema:"Either 'join' to join an existing team or 'create' to make a new one."`
	Name     string `json:"name" jsonschema:"The team name. For 'join' this must match the existing team exactly."`
	Password string `json:"password" jsonschema:"The team's join password. For 'create' this becomes the password teammates use to join."`
	Confirm  bool   `json:"confirm,omitempty" jsonschema:"Must be set to true to proceed. Joining a team is effectively permanent: CTFd does not let a player leave, and all solves become shared."`
}

// TeamOut describes a team.
type TeamOut struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	Affiliation string   `json:"affiliation,omitempty"`
	Country     string   `json:"country,omitempty"`
	CaptainID   *int     `json:"captain_id,omitempty"`
	MemberCount int      `json:"member_count"`
	Members     []string `json:"members,omitempty"`
}

func (s *Server) registerManagementTools() {
	addTool(s, &mcp.Tool{
		Name:        "ctfd_list_tokens",
		Title:       "List API tokens",
		Annotations: readOnly("List API tokens"),
		Description: "List the API tokens on your account, with their descriptions and expiry dates. " +
			"Token values are never shown - CTFd stores them hashed and reveals the plaintext only at creation.",
	}, s.listTokens)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_create_token",
		Title:       "Create an API token",
		Annotations: mutating("Create an API token", false),
		Description: "Mint a new CTFd API token. Useful for turning a password login into a durable credential: " +
			"token authentication is more reliable than a session because it needs no CSRF nonce and does not expire with the session. " +
			"The plaintext value is returned once and cannot be retrieved again.",
	}, s.createToken)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_revoke_token",
		Title:       "Revoke an API token",
		Annotations: mutating("Revoke an API token", true),
		Description: "Delete an API token. Immediate and irreversible. Revoking the token this server is currently " +
			"authenticated with will break the connection.",
	}, s.revokeToken)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_update_profile",
		Title:       "Update your profile",
		Annotations: mutating("Update your profile", true),
		Description: "Change your own account details: display name, website, affiliation, country, email, or password. " +
			"Only the fields you provide are changed. CTFd requires your current password to change the email or password.",
	}, s.updateProfile)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_my_team",
		Title:       "My team",
		Annotations: readOnly("My team"),
		Description: "Your team and its members, in a team-mode event. Reports clearly when the event is in user mode " +
			"or when your account has not joined a team yet.",
	}, s.myTeam)

	addTool(s, &mcp.Tool{
		Name:        "ctfd_join_or_create_team",
		Title:       "Join or create a team",
		Annotations: mutating("Join or create a team", false),
		Description: "Join an existing team with its name and join password, or create a new one. Team-mode events only. " +
			"This is effectively permanent - CTFd provides no way for a player to leave a team - so confirm with the user first.",
	}, s.joinOrCreateTeam)
}

func (s *Server) listTokens(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListTokensOut, error) {
	var out ListTokensOut

	tokens, err := s.deps.Client.Tokens(ctx)
	if err != nil {
		return nil, out, err
	}
	now := time.Now()
	for _, t := range tokens {
		out.Tokens = append(out.Tokens, TokenInfo{
			ID:          t.ID,
			Description: t.Description,
			Created:     formatDate(t.Created),
			Expiration:  formatDate(t.Expiration),
			Expired:     t.Expired(now),
		})
	}
	out.Count = len(out.Tokens)

	var b strings.Builder
	b.WriteString("# API tokens\n\n")
	if out.Count == 0 {
		b.WriteString("No API tokens on this account.\n\nUse ctfd_create_token to mint one.\n")
		return textResult(b.String()), out, nil
	}
	rows := make([][]string, 0, len(out.Tokens))
	for _, t := range out.Tokens {
		status := "active"
		if t.Expired {
			status = "EXPIRED"
		}
		rows = append(rows, []string{itoa(t.ID), t.Description, t.Created, t.Expiration, status})
	}
	b.WriteString(table([]string{"ID", "Description", "Created", "Expires", "Status"}, rows))
	b.WriteString("\nToken values are not retrievable; CTFd shows them only at creation.\n")
	return textResult(b.String()), out, nil
}

func (s *Server) createToken(ctx context.Context, _ *mcp.CallToolRequest, in CreateTokenIn) (*mcp.CallToolResult, CreateTokenOut, error) {
	var out CreateTokenOut

	if !in.Confirm {
		return textResult(
			"No token was created: confirm was not set.\n\n" +
				"An API token is a long-lived credential that grants full access to your CTFd account. " +
				"Ask the user whether to create one, then call again with confirm=true.",
		), out, nil
	}
	if in.Expiration != "" {
		if _, err := time.Parse("2006-01-02", in.Expiration); err != nil {
			return nil, out, fmt.Errorf("expiration must be formatted as YYYY-MM-DD, got %q", in.Expiration)
		}
	}

	t, err := s.deps.Client.CreateToken(ctx, in.Description, in.Expiration)
	if err != nil {
		return nil, out, err
	}
	out = CreateTokenOut{
		ID:          t.ID,
		Description: t.Description,
		Expiration:  formatDate(t.Expiration),
		Value:       t.Value,
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Created API token %d.\n\n", t.ID)
	if t.Description != "" {
		fmt.Fprintf(&b, "- Description: %s\n", t.Description)
	}
	if t.Expiration != "" {
		fmt.Fprintf(&b, "- Expires: %s\n", formatDate(t.Expiration))
	}
	// The value is deliberately shown here: CTFd never reveals it again, and
	// producing it is the entire point of the call. Redaction applies to logs
	// and error messages, not to a tool's successful output, so this survives
	// while the same string is scrubbed everywhere else.
	fmt.Fprintf(&b, "\nToken value (shown once, store it now):\n\n    %s\n", t.Value)
	b.WriteString("\nTo use it, set CTFD_TOKEN to this value and restart the server. " +
		"Token authentication is more reliable than a password session.\n")
	return textResult(b.String()), out, nil
}

func (s *Server) revokeToken(ctx context.Context, _ *mcp.CallToolRequest, in RevokeTokenIn) (*mcp.CallToolResult, struct{}, error) {
	var out struct{}

	if in.TokenID <= 0 {
		return nil, out, fmt.Errorf("token_id must be a positive integer, got %d", in.TokenID)
	}
	if !in.Confirm {
		return textResult(fmt.Sprintf(
			"Token %d was not revoked: confirm was not set.\n\n"+
				"Revoking is immediate and irreversible, and breaks anything still using the token. "+
				"Ask the user, then call again with confirm=true.", in.TokenID,
		)), out, nil
	}

	if err := s.deps.Client.RevokeToken(ctx, in.TokenID); err != nil {
		return nil, out, err
	}
	return textResult(fmt.Sprintf("Token %d has been revoked.", in.TokenID)), out, nil
}

func (s *Server) updateProfile(ctx context.Context, _ *mcp.CallToolRequest, in UpdateProfileIn) (*mcp.CallToolResult, ProfileOut, error) {
	var out ProfileOut

	upd := ctfd.ProfileUpdate{
		Name:        in.Name,
		Email:       in.Email,
		Website:     in.Website,
		Affiliation: in.Affiliation,
		Country:     in.Country,
		Password:    in.NewPassword,
		Confirm:     in.CurrentPassword,
	}
	// Register the supplied secrets so they cannot echo back through an error.
	if in.NewPassword != "" {
		s.red.Add(in.NewPassword)
	}
	if in.CurrentPassword != "" {
		s.red.Add(in.CurrentPassword)
	}

	u, err := s.deps.Client.UpdateProfile(ctx, upd)
	if err != nil {
		return nil, out, err
	}
	out = ProfileOut{
		ID: u.ID, Name: u.Name, Email: u.Email,
		Website: u.Website, Affiliation: u.Affiliation, Country: u.Country,
	}

	var b strings.Builder
	b.WriteString("Profile updated.\n\n")
	fmt.Fprintf(&b, "- Name: %s\n", u.Name)
	if u.Email != "" {
		fmt.Fprintf(&b, "- Email: %s\n", u.Email)
	}
	if u.Affiliation != "" {
		fmt.Fprintf(&b, "- Affiliation: %s\n", u.Affiliation)
	}
	if u.Country != "" {
		fmt.Fprintf(&b, "- Country: %s\n", u.Country)
	}
	if u.Website != "" {
		fmt.Fprintf(&b, "- Website: %s\n", u.Website)
	}
	if in.NewPassword != "" {
		b.WriteString("\nThe password was changed. If this server is authenticating with a password, " +
			"update CTFD_PASSWORD before restarting it.\n")
	}
	return textResult(b.String()), out, nil
}

func (s *Server) myTeam(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, TeamOut, error) {
	var out TeamOut

	if s.detectMode(ctx, nil) == ctfd.ModeUsers {
		return textResult("This event is in user mode, so there are no teams. Use ctfd_whoami for your own standing."), out, nil
	}

	team, err := s.deps.Client.MyTeam(ctx)
	if err != nil {
		if ctfd.IsForbidden(err) || ctfd.IsNotFound(err) {
			return textResult(
				"Your account has not joined a team yet.\n\n" +
					"In a team-mode event CTFd rejects challenge reads and flag submissions until you do. " +
					"Use ctfd_join_or_create_team to join an existing team or create one.",
			), out, nil
		}
		return nil, out, err
	}

	out = TeamOut{
		ID: team.ID, Name: team.Name, Affiliation: team.Affiliation,
		Country: team.Country, CaptainID: team.CaptainID, MemberCount: len(team.Members),
	}

	// Member names need a second call; a failure here is not worth failing the
	// whole tool over.
	if members, merr := s.deps.Client.TeamMembers(ctx); merr == nil {
		for _, m := range members {
			out.Members = append(out.Members, m.Name)
		}
		out.MemberCount = len(members)
	} else {
		s.log.Debug("could not read team members", "error", s.red.Error(merr))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", team.Name)
	fmt.Fprintf(&b, "- Team ID: %d\n", team.ID)
	if team.Affiliation != "" {
		fmt.Fprintf(&b, "- Affiliation: %s\n", team.Affiliation)
	}
	if team.Country != "" {
		fmt.Fprintf(&b, "- Country: %s\n", team.Country)
	}
	fmt.Fprintf(&b, "- Members: %d\n", out.MemberCount)
	if len(out.Members) > 0 {
		fmt.Fprintf(&b, "\n%s\n", strings.Join(out.Members, ", "))
	}
	b.WriteString("\nIn team mode all solves, hint unlocks, and points are shared across the team.\n")
	return textResult(b.String()), out, nil
}

func (s *Server) joinOrCreateTeam(ctx context.Context, _ *mcp.CallToolRequest, in TeamActionIn) (*mcp.CallToolResult, TeamOut, error) {
	var out TeamOut

	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action != "join" && action != "create" {
		return nil, out, fmt.Errorf("action must be 'join' or 'create', got %q", in.Action)
	}
	if in.Name == "" || in.Password == "" {
		return nil, out, fmt.Errorf("both name and password are required")
	}
	s.red.Add(in.Password)

	if s.detectMode(ctx, nil) == ctfd.ModeUsers {
		return nil, out, fmt.Errorf("this event is in user mode, so teams do not apply")
	}
	if !in.Confirm {
		verb := "Joining"
		if action == "create" {
			verb = "Creating"
		}
		return textResult(fmt.Sprintf(
			"Nothing was done: confirm was not set.\n\n"+
				"%s a team is effectively permanent - CTFd gives players no way to leave a team afterwards, "+
				"and from then on all solves and points are shared. Ask the user, then call again with confirm=true.", verb,
		)), out, nil
	}

	var team *ctfd.Team
	var err error
	if action == "join" {
		team, err = s.deps.Client.JoinTeam(ctx, in.Name, in.Password)
	} else {
		team, err = s.deps.Client.CreateTeam(ctx, in.Name, in.Password)
	}
	if err != nil {
		return nil, out, err
	}

	out = TeamOut{
		ID: team.ID, Name: team.Name, Affiliation: team.Affiliation,
		Country: team.Country, CaptainID: team.CaptainID, MemberCount: len(team.Members),
	}

	past := "Joined"
	if action == "create" {
		past = "Created"
	}
	return textResult(fmt.Sprintf(
		"%s team %q (ID %d).\n\nSolves, hint unlocks, and points are now shared across the team.",
		past, team.Name, team.ID,
	)), out, nil
}
