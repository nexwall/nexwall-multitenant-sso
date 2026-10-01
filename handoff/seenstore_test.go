package handoff

import (
	"testing"
	"time"
)

func TestMemorySeenStoreBasic(t *testing.T) {
	s := NewMemorySeenStore()
	exp := time.Now().Add(time.Minute)

	fresh, err := s.CheckAndMark("jti-1", exp)
	if err != nil {
		t.Fatalf("CheckAndMark: %v", err)
	}
	if !fresh {
		t.Error("first CheckAndMark for a new jti should return fresh=true")
	}

	fresh, err = s.CheckAndMark("jti-1", exp)
	if err != nil {
		t.Fatalf("CheckAndMark: %v", err)
	}
	if fresh {
		t.Error("second CheckAndMark for the same jti should return fresh=false")
	}
}

func TestMemorySeenStoreDistinctJTIsIndependent(t *testing.T) {
	s := NewMemorySeenStore()
	exp := time.Now().Add(time.Minute)

	fresh1, _ := s.CheckAndMark("jti-a", exp)
	fresh2, _ := s.CheckAndMark("jti-b", exp)
	if !fresh1 || !fresh2 {
		t.Error("two distinct jtis should both be fresh on first use")
	}
}

// TestMemorySeenStoreConcurrent verifies the atomicity guarantee the
// SeenStore interface promises: when many goroutines race to check the
// same jti, exactly one must see fresh=true.
func TestMemorySeenStoreConcurrent(t *testing.T) {
	s := NewMemorySeenStore()
	exp := time.Now().Add(time.Minute)

	const n = 50
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func() {
			fresh, err := s.CheckAndMark("same-jti", exp)
			if err != nil {
				t.Errorf("CheckAndMark: %v", err)
			}
			results <- fresh
		}()
	}

	freshCount := 0
	for i := 0; i < n; i++ {
		if <-results {
			freshCount++
		}
	}
	if freshCount != 1 {
		t.Errorf("expected exactly 1 goroutine to see fresh=true out of %d, got %d", n, freshCount)
	}
}

func TestMemorySeenStoreEvictsExpiredEntries(t *testing.T) {
	s := NewMemorySeenStore()
	alreadyExpired := time.Now().Add(-time.Minute)

	// Mark it as seen with an expiry in the past.
	if _, err := s.CheckAndMark("old-jti", alreadyExpired); err != nil {
		t.Fatalf("CheckAndMark: %v", err)
	}

	s.mu.Lock()
	_, stillPresent := s.seen["old-jti"]
	s.mu.Unlock()
	if !stillPresent {
		t.Fatal("entry should still be present immediately after insertion, before any later eviction pass")
	}

	// A later call (for a different jti) triggers evictExpiredLocked,
	// which should remove the already-expired entry.
	if _, err := s.CheckAndMark("unrelated-jti", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("CheckAndMark: %v", err)
	}

	s.mu.Lock()
	_, stillPresentAfter := s.seen["old-jti"]
	s.mu.Unlock()
	if stillPresentAfter {
		t.Error("expired entry should have been evicted by a later CheckAndMark call")
	}
}
