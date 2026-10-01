package handoff

import (
	"sync"
	"time"
)

// SeenStore enforces single-use tokens by remembering which JTIs have
// already been redeemed. CheckAndMark must be atomic: it both checks
// whether jti is new and marks it as seen in one operation, so two
// concurrent requests replaying the same token can't both be told "fresh".
//
// Implementations should stop remembering an entry once expiresAt has
// passed -- there's no need to remember a JTI forever, since an expired
// token is already rejected by Verify's own expiry check regardless of
// SeenStore state.
type SeenStore interface {
	// CheckAndMark returns (true, nil) the first time it's called for a
	// given jti, and (false, nil) on every subsequent call for the same
	// jti until expiresAt has passed. expiresAt is provided so
	// implementations know how long they need to remember the entry.
	CheckAndMark(jti string, expiresAt time.Time) (fresh bool, err error)
}

// MemorySeenStore is an in-memory SeenStore, safe for concurrent use.
//
// Important: this only prevents replay within a single process. If
// whatever is calling Verify (nexwall-controller, most likely) ever runs
// more than one replica, a replayed token could succeed against a
// *different* replica that hasn't seen it yet. For a multi-replica
// deployment, implement SeenStore against a shared store instead (e.g.
// Redis with an atomic check-and-set and a TTL matching expiresAt) --
// not built here speculatively, since nothing in this project needs it
// yet; add it when a real multi-replica deployment actually exists.
type MemorySeenStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiresAt
}

// NewMemorySeenStore returns an empty, ready-to-use MemorySeenStore.
// Create one instance per process and reuse it for every Verify call --
// don't create a new one per request, or single-use enforcement won't
// actually track anything across requests.
func NewMemorySeenStore() *MemorySeenStore {
	return &MemorySeenStore{
		seen: make(map[string]time.Time),
	}
}

// CheckAndMark implements SeenStore.
func (s *MemorySeenStore) CheckAndMark(jti string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.evictExpiredLocked()

	if _, exists := s.seen[jti]; exists {
		return false, nil
	}
	s.seen[jti] = expiresAt
	return true, nil
}

// evictExpiredLocked removes entries whose token has already expired.
// Callers must hold s.mu. This keeps the map from growing unbounded in a
// long-running process without needing a separate cleanup goroutine --
// cost is paid incrementally, a little on each call, rather than all at
// once on a timer.
func (s *MemorySeenStore) evictExpiredLocked() {
	now := time.Now().UTC()
	for jti, exp := range s.seen {
		if exp.Before(now) {
			delete(s.seen, jti)
		}
	}
}
