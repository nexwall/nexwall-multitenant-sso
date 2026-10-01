# ADR 0001: A shared Go package instead of two independent implementations

**Status**: Accepted

## Context

`nexwall-partner-multitenant`'s ADR 0006 and `nexwall-controller`'s ADR
0001 both specify the same signed-handoff-token contract (per-tenant
secret, short TTL, single-use via `jti`) from two different sides: one
mints the token, the other validates it. Implementing this contract twice,
independently, in two different repos risks the two sides drifting apart
over time — a claims field renamed on one side and not the other, a
different TTL interpretation, a replay check present on one side and
forgotten on the other. That's exactly the kind of bug that's invisible in
code review (each repo's own tests pass on their own) and only shows up as
a real authentication bypass or a confusing production failure.

## Decision

One shared Go module, `github.com/nexwall/nexwall-multitenant-sso`,
imported by both repos. `handoff.Sign` and `handoff.Verify` are the same
code on both sides, by construction — there is no "the two sides agree
this is how it works", there's only one implementation.

## Design choices worth explaining

- **Not a general JWT library.** This package hardcodes HMAC-SHA256 with
  no algorithm negotiation and no parseable/attacker-controlled header.
  Both sides of this exchange are code we control (not a third-party JWT
  consumer), so full JWT interoperability was never a real requirement —
  and narrowing the format this way removes an entire class of known JWT
  implementation vulnerabilities (algorithm confusion, `"alg": "none"`,
  etc.) by construction, not by careful configuration that could later be
  misconfigured.
- **Zero external dependencies.** Standard library only (`crypto/hmac`,
  `crypto/subtle`, `crypto/rand`, `encoding/json`, `encoding/base64`). For
  a small, security-sensitive shared package imported by two different
  services with two different licenses (`nexwall-partner-multitenant` is
  AGPL-3.0, `nexwall-controller` is GPL-3.0), avoiding a dependency tree is
  both an auditability win and a license-compatibility simplification.
- **License: MIT.** This package contains no code derived from either
  `NethServer/my` or NethSecurity/`nexwall-controller` — it's new code
  implementing a contract designed specifically for this project. MIT
  (rather than matching either consuming repo's copyleft license) keeps it
  freely importable by both an AGPL-3.0 project and a GPL-3.0 project
  without raising any license-combination questions on either side.
- **Replay prevention is pluggable (`SeenStore` interface), not baked in.**
  The included `MemorySeenStore` is correct for a single-process
  deployment but explicitly does NOT protect against replay across
  multiple replicas of the same service — documented clearly in its own
  doc comment, not left as a silent gap. A Redis-backed `SeenStore` is a
  natural future addition once `nexwall-controller` or the Partner Program
  actually runs multiple replicas; not built speculatively before that's a
  real need.
- **Verify returns generic errors.** Every failure path (bad signature,
  expired, wrong tenant, malformed, replayed) returns the same
  undifferentiated `"handoff: invalid token"` externally, rather than
  telling a caller (and therefore potentially whoever is holding a stolen
  or expired URL) exactly which check failed.

## Consequences

- Both `nexwall-partner-multitenant` and `nexwall-controller` take a
  `go.mod` dependency on this repo via a tagged release (e.g. `v0.1.0`) —
  pin a version, don't track `main`, so a change here can't silently break
  either consumer without a deliberate version bump on their side.
- Any future change to the token contract (a new claim, a different replay
  strategy) happens here once, with its own tests, then both consumers
  bump their dependency version deliberately — not two parallel,
  potentially-diverging edits in two repos.
- Neither consuming repo has actually integrated this package yet as of
  this commit — this repo exists and is tested, but the Phase 1.6/Phase 2
  work in `nexwall-partner-multitenant` and the new `/sso/handoff` endpoint
  in `nexwall-controller` (its own ADR 0001) are still pending.
