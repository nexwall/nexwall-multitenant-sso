# nexwall-multitenant-sso

Shared Go package implementing the signed "SSO handoff" token used to move
an authenticated user from the Nexwall Partner Program
(`partner.nexwall.com.br`, repo `nexwall-partner-multitenant`) directly
into a specific customer's own `nexwall-controller` instance, without a
second login screen — the same pattern Sophos Central uses: log in once,
land directly in your own tenant.

See `docs/adr/0001-shared-handoff-token-package.md` for why this is a
separate shared package rather than two independent implementations, and
for the specific design choices (not a general JWT library, zero
dependencies, MIT license, pluggable replay prevention).

## Usage

### Minting a token (Partner Program side)

```go
import "github.com/nexwall/nexwall-multitenant-sso/handoff"

token, err := handoff.Sign(tenantSecret, handoff.Claims{
    Subject:  user.Email,
    TenantID: tenant.ID,
    Role:     user.Role,
}, handoff.DefaultTTL)
if err != nil {
    // handle error
}

redirectURL := fmt.Sprintf("https://%s/sso/handoff?token=%s", tenant.Subdomain, token)
http.Redirect(w, r, redirectURL, http.StatusFound)
```

### Validating a token (nexwall-controller side)

```go
import "github.com/nexwall/nexwall-multitenant-sso/handoff"

// Create once per process and reuse for every request -- not per-request.
var seen = handoff.NewMemorySeenStore()

func handleSSOHandoff(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")

    claims, err := handoff.Verify(tenantSecret, token, thisTenantID, seen)
    if err != nil {
        http.Error(w, "invalid or expired token", http.StatusUnauthorized)
        return
    }

    // claims.Subject and claims.Role are now trusted. Mint this instance's
    // own normal session (e.g. via the existing gin-jwt flow) and redirect
    // to the dashboard, exactly as a successful local login would.
}
```

### Generating a per-tenant secret (Management Plane side, at provisioning time)

```go
secret, err := handoff.GenerateSecret()
// store `secret` and deliver it to BOTH the Partner Program and this
// tenant's nexwall-controller instance -- e.g. as a Kubernetes Secret
// injected into the controller's Helm release, and as a column on the
// Partner Program's Customer-org record.
```

## Important operational notes

- **`tenantSecret` is per-tenant, never global.** A leaked secret should
  only ever compromise the one tenant it belongs to. See ADR 0006 in
  `nexwall-partner-multitenant` for the full rationale.
- **`MemorySeenStore` only prevents replay within a single process.** If
  `nexwall-controller` (or whatever calls `Verify`) ever runs multiple
  replicas, implement the `SeenStore` interface against a shared store
  (Redis, etc.) instead — see its doc comment in `handoff/seenstore.go`.
- Tokens are deliberately short-lived (`DefaultTTL` = 45s) and single-use,
  because they travel as a URL query parameter and can leak via browser
  history, `Referer` headers, or access logs.

## Status

Not yet imported by either consuming repo. This package exists, is tested,
and is ready to depend on, but the integration work on each side (Phase 1.6
/ Phase 2 in `nexwall-partner-multitenant`; the new `/sso/handoff` endpoint
in `nexwall-controller`, per that repo's own
`docs/adr/0001-sso-handoff-from-partner-program.md`) is still pending.

**This package has not been compiled or run with an actual Go toolchain
yet** — it was written in an environment without network access or a Go
installation available. Run `go vet ./... && go test ./...` before pushing
or depending on it. The test suite covers: round-trip sign/verify, expired
tokens, wrong-tenant tokens, tampered signatures, tampered payloads, wrong
secret, replay, malformed input, and `MemorySeenStore`'s concurrency
guarantee.

## License

MIT — see `LICENSE`. This package contains no code derived from
`NethServer/my` or NethSecurity/`nexwall-controller`; it's new code
implementing a contract designed specifically for this project. See the ADR
for why MIT specifically (free importability by both an AGPL-3.0 and a
GPL-3.0 consumer, without raising license-combination questions).
