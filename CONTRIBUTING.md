# Contributing

This is a small, security-sensitive shared package used by both
`nexwall-partner-multitenant` (signs tokens) and `nexwall-controller`
(verifies tokens) — see `docs/adr/0001-shared-handoff-token-package.md`.

Before changing anything in `handoff/`:

1. **Both consumers pin a specific tagged version of this module.** A
   change here does not take effect anywhere until both repos deliberately
   bump their `go.mod` to the new tag — there's no "accidentally shipped a
   breaking change" risk, but also no free lunch: remember to actually bump
   both when you tag a new release that either side needs.
2. **Run `go vet ./... && go test ./...`** — the test suite specifically
   covers the failure modes that matter for this package (expired, wrong
   tenant, tampered signature, tampered payload, wrong secret, replay,
   malformed input). Don't remove or weaken any of them without a very
   good, written-down reason.
3. **Keep this package dependency-free** (standard library only) unless
   there's a compelling reason not to — see the ADR for why.
4. **Tag a release** (`git tag vX.Y.Z && git push origin vX.Y.Z`) for
   anything consumers need to pick up — `main` is not meant to be imported
   directly by either consuming repo.
5. If you change the `Claims` shape or the token format itself, update
   both this repo's tests AND flag the breaking change explicitly in the
   tag/release notes — the two consuming repos are maintained somewhat
   independently and won't necessarily notice a silent contract change.
