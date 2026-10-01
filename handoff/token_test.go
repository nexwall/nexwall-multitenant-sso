package handoff

import (
	"testing"
	"time"
)

func testSecret() []byte {
	return []byte("test-secret-at-least-32-bytes-long!!")
}

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "admin@customer.example", TenantID: "tenant-123", Role: "admin"}

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token == "" {
		t.Fatal("Sign returned an empty token")
	}

	got, err := Verify(secret, token, "tenant-123", NewMemorySeenStore())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != claims.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, claims.Subject)
	}
	if got.TenantID != claims.TenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, claims.TenantID)
	}
	if got.Role != claims.Role {
		t.Errorf("Role = %q, want %q", got.Role, claims.Role)
	}
	if got.JTI == "" {
		t.Error("JTI should be set by Sign")
	}
	if got.IssuedAt == 0 || got.ExpiresAt == 0 {
		t.Error("IssuedAt/ExpiresAt should be set by Sign")
	}
}

func TestSignRequiresSubjectAndTenant(t *testing.T) {
	secret := testSecret()

	if _, err := Sign(secret, Claims{TenantID: "t1"}, time.Minute); err == nil {
		t.Error("expected error for missing Subject, got nil")
	}
	if _, err := Sign(secret, Claims{Subject: "a@b.com"}, time.Minute); err == nil {
		t.Error("expected error for missing TenantID, got nil")
	}
}

func TestSignRequiresSecret(t *testing.T) {
	if _, err := Sign(nil, Claims{Subject: "a@b.com", TenantID: "t1"}, time.Minute); err == nil {
		t.Error("expected error for empty secret, got nil")
	}
}

func TestDefaultTTLUsedWhenNonPositive(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := Verify(secret, token, "t1", NewMemorySeenStore())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	gotTTL := time.Duration(got.ExpiresAt-got.IssuedAt) * time.Second
	if gotTTL != DefaultTTL {
		t.Errorf("TTL = %v, want DefaultTTL (%v)", gotTTL, DefaultTTL)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, -time.Second) // already expired
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := Verify(secret, token, "t1", NewMemorySeenStore()); err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestVerifyRejectsWrongTenant(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := Verify(secret, token, "t2", NewMemorySeenStore()); err == nil {
		t.Error("expected error for mismatched tenant, got nil")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := token[:len(token)-2] + "xx"
	if _, err := Verify(secret, tampered, "t1", NewMemorySeenStore()); err == nil {
		t.Error("expected error for tampered signature, got nil")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		t.Fatal("splitToken failed on our own well-formed token")
	}
	tampered := payloadB64 + "AAAA" + "." + sigB64
	if _, err := Verify(secret, tampered, "t1", NewMemorySeenStore()); err == nil {
		t.Error("expected error for tampered payload, got nil")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}
	token, err := Sign(testSecret(), claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	otherSecret := []byte("a-completely-different-secret-value")
	if _, err := Verify(otherSecret, token, "t1", NewMemorySeenStore()); err == nil {
		t.Error("expected error for wrong secret, got nil")
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}
	seen := NewMemorySeenStore()

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := Verify(secret, token, "t1", seen); err != nil {
		t.Fatalf("first Verify should succeed: %v", err)
	}
	if _, err := Verify(secret, token, "t1", seen); err == nil {
		t.Error("second Verify of the same token should fail (replay), got nil")
	}
}

func TestVerifySkipsReplayCheckWhenSeenIsNil(t *testing.T) {
	secret := testSecret()
	claims := Claims{Subject: "a@b.com", TenantID: "t1"}

	token, err := Sign(secret, claims, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := Verify(secret, token, "t1", nil); err != nil {
		t.Fatalf("first Verify with nil SeenStore should succeed: %v", err)
	}
	if _, err := Verify(secret, token, "t1", nil); err != nil {
		t.Fatalf("second Verify with nil SeenStore should also succeed (no replay check): %v", err)
	}
}

func TestVerifyMalformedToken(t *testing.T) {
	secret := testSecret()
	cases := []string{
		"",
		"no-dot-at-all",
		"not-base64!!!.also-not-base64!!!",
		".",
	}
	for _, tc := range cases {
		if _, err := Verify(secret, tc, "t1", NewMemorySeenStore()); err == nil {
			t.Errorf("Verify(%q): expected error, got nil", tc)
		}
	}
}

func TestGenerateSecretIsRandomAndCorrectLength(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == b {
		t.Error("two calls to GenerateSecret produced the same value")
	}
	if len(a) == 0 {
		t.Error("GenerateSecret returned an empty string")
	}
}
