package mcpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// maxTrackedChallenges bounds the attempt log's memory.
const maxTrackedChallenges = 4096

// attemptLog records which flags this process has already submitted for each
// challenge.
//
// This exists because attempts are a scarce, irreversible resource: many CTFd
// challenges cap max_attempts, and a model that loses track of what it tried
// can burn the budget resubmitting the same wrong string. The log lets
// ctfd_submit_flag refuse a duplicate before it reaches the network.
//
// Flags are stored hashed, never in plaintext, so a memory dump or a log of
// this structure does not disclose solved answers.
type attemptLog struct {
	mu sync.Mutex
	// byChallenge maps challenge ID to that challenge's attempt record.
	byChallenge map[int]*challengeAttempts
	now         func() time.Time
}

type challengeAttempts struct {
	// tried maps a normalized flag hash to when it was first submitted.
	tried map[string]attemptRecord
	// solved records that a correct flag has already been accepted.
	solved bool
	// count is the number of submissions made through this server.
	count int
	last  time.Time
}

type attemptRecord struct {
	at      time.Time
	outcome string
}

func newAttemptLog() *attemptLog {
	return &attemptLog{byChallenge: make(map[int]*challengeAttempts), now: time.Now}
}

// normalize canonicalizes a flag for duplicate detection. Surrounding
// whitespace is insignificant, but case and interior characters are not:
// CTFd's default comparison is case-sensitive, and a case-only difference is a
// genuinely different attempt.
func normalize(flag string) string {
	return strings.TrimSpace(flag)
}

func fingerprint(flag string) string {
	sum := sha256.Sum256([]byte(normalize(flag)))
	return hex.EncodeToString(sum[:])
}

// PriorAttempt reports whether this exact flag was already submitted for this
// challenge, and if so when and with what outcome.
func (l *attemptLog) PriorAttempt(challengeID int, flag string) (attemptRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.byChallenge[challengeID]
	if !ok {
		return attemptRecord{}, false
	}
	r, ok := c.tried[fingerprint(flag)]
	return r, ok
}

// AlreadySolved reports whether a correct flag was already accepted for this
// challenge during this session.
func (l *attemptLog) AlreadySolved(challengeID int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.byChallenge[challengeID]
	return ok && c.solved
}

// Record notes a submission and its outcome.
func (l *attemptLog) Record(challengeID int, flag, outcome string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.byChallenge[challengeID]
	if !ok {
		if len(l.byChallenge) >= maxTrackedChallenges {
			l.evictLocked()
		}
		c = &challengeAttempts{tried: make(map[string]attemptRecord)}
		l.byChallenge[challengeID] = c
	}
	now := l.now()
	c.tried[fingerprint(flag)] = attemptRecord{at: now, outcome: outcome}
	c.count++
	c.last = now
	if outcome == "correct" || outcome == "already_solved" {
		c.solved = true
	}
}

// Count reports how many submissions this session has made for a challenge.
func (l *attemptLog) Count(challengeID int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.byChallenge[challengeID]; ok {
		return c.count
	}
	return 0
}

// Summary reports total submissions and distinct challenges touched.
func (l *attemptLog) Summary() (submissions, challenges, solved int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.byChallenge {
		submissions += c.count
		challenges++
		if c.solved {
			solved++
		}
	}
	return
}

// evictLocked drops the least recently used half of the tracked challenges.
// The caller must hold l.mu.
func (l *attemptLog) evictLocked() {
	var cutoff time.Time
	for _, c := range l.byChallenge {
		if cutoff.IsZero() || c.last.Before(cutoff) {
			cutoff = c.last
		}
	}
	// Drop everything older than the midpoint between the oldest entry and
	// now, which approximates an LRU sweep without sorting.
	mid := cutoff.Add(l.now().Sub(cutoff) / 2)
	for id, c := range l.byChallenge {
		if c.last.Before(mid) && !c.solved {
			delete(l.byChallenge, id)
		}
	}
}
