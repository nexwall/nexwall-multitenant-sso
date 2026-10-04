// Package handoff implements the signed, short-lived, single-use "SSO
// handoff" token used to move an authenticated user from the Nexwall
// Partner Program (nexwall-partner-multitenant, partner.nexwall.com.br)
// directly into a specific customer's own nexwall-controller instance,
// without a second login screen -- the same pattern Sophos Central uses:
// log in once, land directly in your own tenant.
//
// Design notes (see docs/adr/0001-shared-handoff-token-package.md for the
// full rationale):
//
//   - HMAC-SHA256 only, hardcoded. This is deliberately NOT a general JWT
//     implementation: no algorithm negotiation, no "alg: none", no
//     parseable/attacker-controlled header. Both sides of this exchange
//     are code we control, so full JWT interoperability was never a real
//     requirement, and narrowing the format this way removes an entire
//     class of known JWT implementation vulnerabilities by construction.
//   - Per-tenant secret, not a global shared secret (see ADR 0006 in
//     nexwall-partner-multitenant): a leaked secret only ever affects one
//     tenant, never every tenant at once.
//   - Short TTL + single-use (via SeenStore, see seenstore.go) because the
//     token travels as a URL query parameter, which can leak through
//     browser history, Referer headers, and access logs.
package handoff

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultTTL is the recommended token lifetime: long enough for a browser
// redirect to complete, short enough that a leaked URL stops being useful
// almost immediately. ADR 0006 (nexwall-partner-multitenant) specifies
// 30-60s; this package defaults to the middle of that range.
const DefaultTTL = 45 * time.Second

// Claims is the payload carried by a handoff token.
type Claims struct {
	// Subject is the authenticated user's identity (their email, matching
	// what the Partner Program's IdP verified).
	Subject string `json:"sub"`

	// TenantID identifies which nexwall-controller instance this token is
	// valid for. Verify always checks this against the expected tenant, so
	// a token minted for one customer can never be accepted by a
	// different one, even before its TTL expires.
	TenantID string `json:"tid"`

	// Role carries whatever role/permission the subject has within this
	// tenant (e.g. "admin"). Interpretation is entirely up to the
	// receiving side -- this package doesn't assign any meaning to it.
	Role string `json:"role,omitempty"`

	// JTI is a random, unique token ID, used for single-use enforcement
	// via a SeenStore. Set by Sign; callers should not set it themselves.
	JTI string `json:"jti"`

	// IssuedAt and ExpiresAt are Unix timestamps (seconds), set by Sign.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// Sign produces a handoff token string for the given claims, signed with
// secret. IssuedAt, ExpiresAt, and JTI are set by this function -- callers
// only need to populate Subject, TenantID, and (optionally) Role. Passing
// ttl == 0 uses DefaultTTL; any other value (including negative, which
// produces an already-expired token -- useful in tests) is honored exactly
// as given, not silently overridden.
func Sign(secret []byte, claims Claims, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("handoff: secret must not be empty")
	}
	if claims.Subject == "" {
		return "", errors.New("handoff: claims.Subject is required")
	}
	if claims.TenantID == "" {
		return "", errors.New("handoff: claims.TenantID is required")
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}

	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("handoff: generating jti: %w", err)
	}

	now := time.Now().UTC()
	claims.JTI = jti
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("handoff: marshaling claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	sig := sign(secret, payloadB64)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64, nil
}

// Verify checks a handoff token's signature, expiry, and tenant match, then
// (if seen is non-nil) enforces single use. It returns the validated claims
// only if every check passes; any failure returns a generic error without
// distinguishing which check failed, so callers don't leak validation
// details to whoever's holding the token.
//
// expectedTenantID should be the receiving nexwall-controller instance's
// own tenant ID -- Verify rejects any token not minted for this specific
// tenant, even if the signature and expiry are otherwise valid.
//
// Passing seen == nil skips single-use enforcement entirely -- only do this
// in tests. Production callers should always pass a real SeenStore.
func Verify(secret []byte, token string, expectedTenantID string, seen SeenStore) (*Claims, error) {
	if len(secret) == 0 {
		return nil, errors.New("handoff: secret must not be empty")
	}

	payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		return nil, errors.New("handoff: invalid token")
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("handoff: invalid token")
	}

	expected := sign(secret, payloadB64)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, errors.New("handoff: invalid token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("handoff: invalid token")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("handoff: invalid token")
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt <= now {
		return nil, errors.New("handoff: invalid token")
	}
	if claims.TenantID != expectedTenantID {
		return nil, errors.New("handoff: invalid token")
	}
	if claims.JTI == "" {
		return nil, errors.New("handoff: invalid token")
	}

	if seen != nil {
		fresh, err := seen.CheckAndMark(claims.JTI, time.Unix(claims.ExpiresAt, 0).UTC())
		if err != nil {
			return nil, fmt.Errorf("handoff: replay check failed: %w", err)
		}
		if !fresh {
			return nil, errors.New("handoff: invalid token")
		}
	}

	return &claims, nil
}

// GenerateSecret returns a new random per-tenant signing secret (256 bits,
// base64url-encoded), suitable for storage as e.g. a Kubernetes Secret
// value. Call this once per tenant at provisioning time
// (nexwall-multi-tenant's Management Plane) and give the same value to
// both the Partner Program (to sign) and that tenant's nexwall-controller
// instance (to verify) -- never reuse one secret across multiple tenants.
func GenerateSecret() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("handoff: generating secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sign(secret []byte, payloadB64 string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	return mac.Sum(nil)
}

// splitToken splits "payload.signature" on the last '.' -- base64url
// output never contains '.', so this is unambiguous.
func splitToken(token string) (payloadB64, sigB64 string, ok bool) {
	i := strings.LastIndexByte(token, '.')
	if i < 0 {
		return "", "", false
	}
	return token[:i], token[i+1:], true
}

func newJTI() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
