package ctfd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Download is the outcome of fetching one challenge attachment.
type Download struct {
	// URL is the resolved source, with any credential query parameter
	// stripped so it is safe to show.
	URL string
	// Path is where the file was written.
	Path string
	// Name is the sanitized base filename.
	Name string
	// Size is the number of bytes written.
	Size int64
	// SHA256 is the hex digest of the content, useful for identifying known
	// files and for reproducibility.
	SHA256 string
	// ContentType is the server-declared type, which is advisory only.
	ContentType string
}

// DownloadFile fetches a challenge attachment into destDir.
//
// fileURL comes from a ChallengeDetail.Files entry and may be either absolute
// or root-relative. The download is constrained in three ways that matter:
// the resolved URL must live on the configured CTFd host, the written path
// must stay inside destDir, and the body is capped at maxBytes.
func (c *Client) DownloadFile(ctx context.Context, fileURL, destDir string, maxBytes int64) (*Download, error) {
	u, err := c.resolveFileURL(fileURL)
	if err != nil {
		return nil, err
	}

	name, err := safeFilename(u.Path)
	if err != nil {
		return nil, err
	}

	absDir, err := filepath.Abs(destDir)
	if err != nil {
		return nil, fmt.Errorf("ctfd: resolving download directory: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return nil, fmt.Errorf("ctfd: creating download directory: %w", err)
	}

	destPath := filepath.Join(absDir, name)
	// Defense in depth: even though safeFilename already rejects separators,
	// confirm the final path is inside the sandbox before creating anything.
	if !isWithin(absDir, destPath) {
		return nil, fmt.Errorf("ctfd: refusing to write outside the download directory: %s", name)
	}

	if err := c.limit.Wait(ctx); err != nil {
		return nil, c.ctxError(request{method: http.MethodGet, path: "files"}, err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, &Error{Kind: KindTransport, Method: http.MethodGet, Path: u.Path, Err: err}
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	// CTFd signs attachment URLs with a ?token= parameter, but authenticating
	// as well keeps downloads working on instances that require a session for
	// the /files route.
	if err := c.authenticate(ctx, req); err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.transportError(request{method: http.MethodGet, path: u.Path}, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{
			Kind:       kindForStatus(resp.StatusCode),
			StatusCode: resp.StatusCode,
			Method:     http.MethodGet,
			Path:       u.Path,
			Message:    "attachment download failed",
		}
	}
	// A challenge attachment should never be an HTML page. When CTFd bounces
	// an unauthenticated download it serves the login page with a 200, which
	// would otherwise be written to disk as if it were the real file.
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		return nil, &Error{
			Kind: KindAuth, StatusCode: resp.StatusCode, Method: http.MethodGet, Path: u.Path,
			Message: "the download returned an HTML page instead of a file, which usually means the signed download token was rejected or has expired",
		}
	}

	// Declared length is only a hint, but when it is present and already over
	// the cap there is no reason to transfer the body at all.
	if resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("ctfd: attachment is %d bytes, over the %d byte limit; raise CTFD_MAX_DOWNLOAD_BYTES to fetch it", resp.ContentLength, maxBytes)
	}

	// Write to a temporary file first so an interrupted or oversized download
	// never leaves a truncated file that looks complete.
	tmp, err := os.CreateTemp(absDir, ".ctfd-mcp-*.part")
	if err != nil {
		return nil, fmt.Errorf("ctfd: creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	hasher := sha256.New()
	// Read one byte past the cap so exceeding it is detectable rather than
	// silently truncating.
	written, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ctfd: downloading attachment: %w", err)
	}
	if written > maxBytes {
		return nil, fmt.Errorf("ctfd: attachment exceeds the %d byte limit; raise CTFD_MAX_DOWNLOAD_BYTES to fetch it", maxBytes)
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("ctfd: flushing attachment: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("ctfd: closing attachment: %w", err)
	}

	finalPath, err := publishWithoutOverwrite(tmpName, destPath)
	if err != nil {
		return nil, fmt.Errorf("ctfd: saving attachment: %w", err)
	}

	// Redact the signed token before the URL is shown to anyone.
	safeURL := *u
	sq := safeURL.Query()
	if sq.Has("token") {
		sq.Set("token", "[REDACTED]")
		safeURL.RawQuery = sq.Encode()
	}

	return &Download{
		URL:         safeURL.String(),
		Path:        finalPath,
		Name:        filepath.Base(finalPath),
		Size:        written,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

// resolveFileURL turns a challenge's file entry into an absolute URL and
// refuses anything that would leave the configured CTFd host.
//
// Challenge data is authored by event organizers. Treating a file entry as a
// blind fetch target would let a malicious challenge point this client at an
// internal address, sending along its credentials.
func (c *Client) resolveFileURL(fileURL string) (*url.URL, error) {
	fileURL = strings.TrimSpace(fileURL)
	if fileURL == "" {
		return nil, fmt.Errorf("ctfd: empty attachment URL")
	}
	ref, err := url.Parse(fileURL)
	if err != nil {
		return nil, fmt.Errorf("ctfd: invalid attachment URL %q: %w", fileURL, err)
	}
	u := c.base.ResolveReference(ref)

	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("ctfd: refusing attachment URL with scheme %q", u.Scheme)
	}
	if !strings.EqualFold(u.Host, c.base.Host) {
		return nil, fmt.Errorf("ctfd: refusing to download from %q, which is not the configured CTFd host %q", u.Host, c.base.Host)
	}
	return u, nil
}

// safeFilename derives a filesystem-safe base name from a URL path.
func safeFilename(urlPath string) (string, error) {
	// Percent-decode first: an encoded separator would otherwise survive the
	// checks below and reappear once the OS interprets the name.
	decoded, err := url.PathUnescape(urlPath)
	if err != nil {
		decoded = urlPath
	}
	name := path.Base(strings.ReplaceAll(decoded, "\\", "/"))
	name = strings.TrimRight(strings.TrimSpace(name), ". ")

	if name == "" || name == "." || name == ".." || name == "/" {
		return "", fmt.Errorf("ctfd: attachment URL has no usable filename: %q", urlPath)
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("ctfd: refusing attachment filename containing a path separator: %q", name)
	}
	// Reserved device names on Windows resolve to hardware rather than files.
	if isReservedWindowsName(name) {
		name = "_" + name
	}
	// Replace characters that are invalid on Windows or hostile in a shell.
	name = strings.Map(func(r rune) rune {
		switch r {
		case ':', '*', '?', '"', '<', '>', '|', 0:
			return '_'
		}
		if r < 0x20 {
			return '_'
		}
		return r
	}, name)
	// A leading dash makes the file awkward to pass to command-line tools.
	name = strings.TrimLeft(name, "-")
	if name == "" {
		return "", fmt.Errorf("ctfd: attachment filename became empty after sanitization")
	}
	if len(name) > 200 {
		ext := path.Ext(name)
		if len(ext) > 16 {
			ext = ""
		}
		name = name[:200-len(ext)] + ext
	}
	// Truncation can itself expose a trailing space or period that was not at
	// the end of the original name. Windows rejects those names, so normalize
	// once more after applying the length cap.
	name = strings.TrimRight(name, ". ")
	if name == "" {
		return "", fmt.Errorf("ctfd: attachment filename became empty after truncation")
	}
	return name, nil
}

var reservedWindowsNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

func isReservedWindowsName(name string) bool {
	stem := strings.ToLower(name)
	if i := strings.Index(stem, "."); i >= 0 {
		stem = stem[:i]
	}
	return reservedWindowsNames[stem]
}

// isWithin reports whether target is inside dir.
func isWithin(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// publishWithoutOverwrite exposes a completed temporary download at a unique
// filename without ever replacing an existing attachment.
//
// A Stat-then-Rename sequence looks safe but is not: two concurrent downloads
// can both observe the name as free, and Unix Rename overwrites the winner's
// file. Linking the completed temporary file creates the final name atomically
// with no-overwrite semantics. Some filesystems do not support hard links, so
// the fallback reserves a new file with O_EXCL and copies into that reservation.
func publishWithoutOverwrite(tmpPath, desiredPath string) (string, error) {
	ext := filepath.Ext(desiredPath)
	stem := strings.TrimSuffix(desiredPath, ext)

	for i := 0; i < 10_000; i++ {
		candidate := desiredPath
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}

		if err := os.Link(tmpPath, candidate); err == nil {
			if err := os.Remove(tmpPath); err != nil {
				_ = os.Remove(candidate)
				return "", fmt.Errorf("removing temporary attachment after publishing: %w", err)
			}
			return candidate, nil
		} else if errors.Is(err, fs.ErrExist) {
			continue
		}

		// Hard links are unavailable on some removable and network filesystems.
		// Reserve the target exclusively before copying so that fallback never
		// reintroduces the overwrite race the hard-link path avoids.
		copied, err := copyIntoNewFile(tmpPath, candidate)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !copied {
			return "", fmt.Errorf("could not publish attachment")
		}
		if err := os.Remove(tmpPath); err != nil {
			_ = os.Remove(candidate)
			return "", fmt.Errorf("removing temporary attachment after publishing: %w", err)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("could not find a free filename after 10,000 attempts for %q", filepath.Base(desiredPath))
}

// copyIntoNewFile copies src into dst only when dst did not previously exist.
// It returns false with fs.ErrExist when another download reserved the name.
func copyIntoNewFile(srcPath, dstPath string) (bool, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return false, fmt.Errorf("opening temporary attachment: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = dst.Close()
	}()

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)
		return false, fmt.Errorf("copying attachment into reserved destination: %w", err)
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)
		return false, fmt.Errorf("flushing reserved attachment: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(dstPath)
		return false, fmt.Errorf("closing reserved attachment: %w", err)
	}
	return true, nil
}
