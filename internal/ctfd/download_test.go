package ctfd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSafeFilenameRejectsTraversal(t *testing.T) {
	// Attachment paths come from the CTFd server. An organizer who can name a
	// file must not be able to choose where it lands on disk.
	hostile := []string{
		"/files/../../../../etc/passwd",
		"/files/..%2f..%2fetc%2fpasswd",
		"/files/",
		"/files/.",
		"/files/..",
	}
	for _, p := range hostile {
		name, err := safeFilename(p)
		if err != nil {
			continue // rejected outright, which is fine
		}
		if strings.ContainsAny(name, `/\`) {
			t.Errorf("safeFilename(%q) = %q, which still contains a path separator", p, name)
		}
		if name == ".." || name == "." {
			t.Errorf("safeFilename(%q) = %q, which escapes the sandbox", p, name)
		}
	}
}

func TestSafeFilenameNormalizesHostileNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/files/abcdef/chal.zip", "chal.zip"},
		{"/files/hash/report.pdf", "report.pdf"},
		{"/files/x/CON", "_CON"},              // reserved Windows device name
		{"/files/x/a:b*c?.txt", "a_b_c_.txt"}, // characters invalid on Windows
		{"/files/x/--rf", "rf"},               // leading dashes look like CLI flags
	}
	for _, tc := range cases {
		got, err := safeFilename(tc.in)
		if err != nil {
			t.Errorf("safeFilename(%q) errored: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("safeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsWithin(t *testing.T) {
	dir := filepath.Clean("/sandbox")
	if !isWithin(dir, filepath.Join(dir, "file.txt")) {
		t.Error("a file directly inside the sandbox should be accepted")
	}
	if isWithin(dir, filepath.Join(dir, "..", "escape.txt")) {
		t.Error("a path escaping the sandbox must be rejected")
	}
}

func TestResolveFileURLRefusesForeignHosts(t *testing.T) {
	// A challenge could otherwise point this client at an internal service and
	// have it send along the CTFd credential.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := newTestClient(t, ts, nil)

	if _, err := c.resolveFileURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("expected a foreign host to be refused")
	}
	if _, err := c.resolveFileURL("file:///etc/passwd"); err == nil {
		t.Error("expected a non-HTTP scheme to be refused")
	}
	// A root-relative path from a real challenge response must still resolve.
	u, err := c.resolveFileURL("/files/abc/chal.zip?token=secret")
	if err != nil {
		t.Fatalf("a same-host relative URL should resolve: %v", err)
	}
	if !strings.HasSuffix(u.Path, "/files/abc/chal.zip") {
		t.Errorf("resolved path = %q", u.Path)
	}
}

func TestDownloadFileWritesAndHashes(t *testing.T) {
	const content = "PK\x03\x04 pretend zip payload"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	dir := t.TempDir()

	d, err := c.DownloadFile(context.Background(), "/files/abc/chal.zip?token=supersecret", dir, 1<<20)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if d.Name != "chal.zip" {
		t.Errorf("Name = %q, want chal.zip", d.Name)
	}
	if d.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", d.Size, len(content))
	}
	if !isWithin(dir, d.Path) {
		t.Errorf("file was written outside the sandbox: %s", d.Path)
	}
	got, err := os.ReadFile(d.Path)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(got) != content {
		t.Errorf("content mismatch: got %q", got)
	}
	if strings.Contains(d.URL, "supersecret") {
		t.Errorf("the signed token leaked into the reported URL: %s", d.URL)
	}
	if len(d.SHA256) != 64 {
		t.Errorf("SHA256 = %q, want a 64-character hex digest", d.SHA256)
	}
}

func TestDownloadFileEnforcesSizeCap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// No Content-Length, so the cap must be enforced while streaming.
		for i := 0; i < 100; i++ {
			_, _ = w.Write([]byte(strings.Repeat("A", 1024)))
		}
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	dir := t.TempDir()

	_, err := c.DownloadFile(context.Background(), "/files/x/big.bin", dir, 4096)
	if err == nil {
		t.Fatal("expected the size cap to reject an oversized download")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %q, want it to mention the limit", err)
	}
	// The partial file must not be left behind at all.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		t.Errorf("an oversized download left %q behind", e.Name())
	}
}

func TestDownloadFileRejectsHTMLLoginPage(t *testing.T) {
	// CTFd serves the login page with a 200 when a download token is rejected.
	// Saving that as if it were the attachment would be silently wrong.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Login</body></html>"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	_, err := c.DownloadFile(context.Background(), "/files/x/chal.zip", t.TempDir(), 1<<20)
	if err == nil {
		t.Fatal("expected an HTML response to be rejected")
	}
	if !IsAuth(err) {
		t.Errorf("expected an auth-kind error, got %v", err)
	}
}

func TestDownloadFileDoesNotOverwrite(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("payload"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	dir := t.TempDir()
	ctx := context.Background()

	first, err := c.DownloadFile(ctx, "/files/a/chal.zip", dir, 1<<20)
	if err != nil {
		t.Fatalf("first download: %v", err)
	}
	second, err := c.DownloadFile(ctx, "/files/b/chal.zip", dir, 1<<20)
	if err != nil {
		t.Fatalf("second download: %v", err)
	}
	if first.Path == second.Path {
		t.Error("a second download with the same name must not overwrite the first")
	}
	if _, err := os.Stat(first.Path); err != nil {
		t.Errorf("the first download was lost: %v", err)
	}
}

func TestDownloadFileDoesNotOverwriteWhenConcurrent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("payload"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts, nil)
	dir := t.TempDir()

	const downloads = 8
	start := make(chan struct{})
	results := make(chan *Download, downloads)
	errs := make(chan error, downloads)
	var wg sync.WaitGroup
	for range downloads {
		wg.Go(func() {
			<-start
			d, err := c.DownloadFile(context.Background(), "/files/a/chal.zip", dir, 1<<20)
			if err != nil {
				errs <- err
				return
			}
			results <- d
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("concurrent download: %v", err)
	}
	seen := make(map[string]bool, downloads)
	for d := range results {
		if seen[d.Path] {
			t.Errorf("two concurrent downloads used %q", d.Path)
		}
		seen[d.Path] = true
		got, err := os.ReadFile(d.Path)
		if err != nil {
			t.Errorf("reading %q: %v", d.Path, err)
		} else if string(got) != "payload" {
			t.Errorf("content of %q = %q, want payload", d.Path, got)
		}
	}
	if len(seen) != downloads {
		t.Errorf("saved %d files, want %d", len(seen), downloads)
	}
}
