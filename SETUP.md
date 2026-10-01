# Setup instructions (run these on the VM)

This archive already contains a git repository with one commit — the
`.git` folder is included, so you don't need to run `git init` again.

## 1. Extract

```bash
tar xzf nexwall-multitenant-sso.tar.gz
cd nexwall-multitenant-sso
git log --oneline   # should show one commit: "Initial implementation..."
```

## 2. Test before pushing — important

This code was written in an environment with no Go toolchain and no
network access, so it has **not** been compiled or run yet. Do this first:

```bash
go vet ./...
go test ./... -v
```

If `go` isn't installed on the VM:

```bash
sudo apt-get update && sudo apt-get install -y golang-go
go version   # confirm it's at least 1.22; if older, see note below
```

If the installed Go is older than 1.22 and complains about `go.mod`'s `go
1.22` directive, either install a newer Go (via https://go.dev/dl/ — the
official binary release, not apt) or temporarily edit `go.mod`'s version
line to match what's installed, run the tests, then put it back before
committing anything.

All 20 tests should pass. If any fail, **do not push** — read the failure,
fix it, re-run, and only then proceed. This is security-sensitive code
shared between two services; don't skip this step.

## 3. Push to GitHub

Assuming the empty repo `nexwall-multitenant-sso` already exists under the
`nexwall` org (same as the other repos):

```bash
git remote add origin git@github.com:nexwall/nexwall-multitenant-sso.git
git push -u origin main
```

## 4. Tag the first release

Both consuming repos (`nexwall-partner-multitenant`,
`nexwall-controller`) should depend on a tagged version, not `main` — see
`CONTRIBUTING.md`.

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 5. Next steps (not part of this package)

- In `nexwall-partner-multitenant`: add `require
  github.com/nexwall/nexwall-multitenant-sso v0.1.0` and implement Phase
  1.6 / Phase 2's handoff-minting logic using `handoff.Sign`.
- In `nexwall-controller`: same dependency, implement the `/sso/handoff`
  endpoint from that repo's `docs/adr/0001-sso-handoff-from-partner-
  program.md` using `handoff.Verify`.
