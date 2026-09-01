//go:build ctfdintegration

package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRealCTFdPasswordLoginSmoke drives the compiled MCP server against an
// unmodified CTFd Docker image. The CI bootstrapper creates a regular player
// and one challenge with a known flag; this checks the browser-login session,
// regular challenge reads, real flag submission, and the submissions fallback
// CTFd uses before it exposed users/me/submissions in 3.8.
func TestRealCTFdPasswordLoginSmoke(t *testing.T) {
	ctfdURL := requiredIntegrationEnv(t, "CTFD_INTEGRATION_URL")
	username := requiredIntegrationEnv(t, "CTFD_INTEGRATION_USERNAME")
	password := requiredIntegrationEnv(t, "CTFD_INTEGRATION_PASSWORD")
	flag := requiredIntegrationEnv(t, "CTFD_INTEGRATION_FLAG")
	challengeID, err := strconv.Atoi(requiredIntegrationEnv(t, "CTFD_INTEGRATION_CHALLENGE_ID"))
	if err != nil || challengeID <= 0 {
		t.Fatalf("CTFD_INTEGRATION_CHALLENGE_ID must be a positive integer: %v", err)
	}

	bin := buildBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"CTFD_URL="+ctfdURL,
		"CTFD_USERNAME="+username,
		"CTFD_PASSWORD="+password,
		"CTFD_TOKEN=",
		"CTFD_SESSION=",
		"CTFD_CACHE_TTL=0",
		"CTFD_LOG_LEVEL=error",
	)
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "ctfd-live-smoke", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to the server subprocess: %v", err)
	}
	defer sess.Close()

	call := func(name string, args map[string]any) string {
		t.Helper()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s transport failure: %v", name, err)
		}
		text := contentText(res)
		if res.IsError {
			t.Fatalf("%s failed against live CTFd:\n%s", name, text)
		}
		return text
	}

	whoami := call("ctfd_whoami", nil)
	if !strings.Contains(whoami, username) || !strings.Contains(whoami, "password-login") {
		t.Fatalf("password login did not authenticate the expected player:\n%s", whoami)
	}

	list := call("ctfd_list_challenges", nil)
	if !strings.Contains(list, "ctfd-mcp live smoke") {
		t.Fatalf("the bootstrap challenge was not visible to the player:\n%s", list)
	}

	detail := call("ctfd_get_challenge", map[string]any{"challenge_id": challengeID})
	if !strings.Contains(detail, "ctfd-mcp live smoke") {
		t.Fatalf("unexpected challenge detail for %d:\n%s", challengeID, detail)
	}

	submission := call("ctfd_submit_flag", map[string]any{
		"challenge_id": challengeID,
		"flag":         flag,
	})
	if !strings.Contains(submission, "CORRECT") {
		t.Fatalf("the known flag was not accepted:\n%s", submission)
	}

	history := call("ctfd_my_submissions", map[string]any{"challenge_id": challengeID})
	if !strings.Contains(history, "CORRECT") {
		t.Fatalf("the successful submission was missing from history:\n%s", history)
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when running with -tags=ctfdintegration", name)
	}
	return value
}
