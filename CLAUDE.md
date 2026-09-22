# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What this is

**tenpm-uptime-monitor** — the open-source agent for tenpm's uptime
monitoring SaaS. A single binary you run anywhere (your own server, a
Raspberry Pi, a NAS) that polls a check schedule from a closed-source central
server and reports results back over a small JSON API. "Bring your own
agent": the agent is public and auditable — no telemetry beyond what it's
explicitly configured to check, and nothing here can reach anything but the
server it's pointed at and the targets it's told to check.

Apache-2.0 licensed. **Not open to outside code contributions at this time**
(see `CONTRIBUTING.md`): no PR process, no CI gating one, no contributor
agreement in place. Feature requests and feedback on the service at
tenpmuptime.com are welcome via issues; code changes are not.

## Working in this repo

This module is meant to stand on its own: it must never depend on the
central server's own codebase, and must never need a SQL driver such as
MySQL (its own storage is SQLite only). `cmd/monitor/boundary_test.go`
checks the dependency graph — including test dependencies — for both and
fails the build if either sneaks in; treat that test as load-bearing, not a
formality.

`model/api.go`'s request/response types are this agent's wire contract with
the central server. No API version exists in the wire format yet, so treat
every change there as if it will break something the moment it ships:
**additive changes only** (a new optional field is fine; removing a field or
changing what one means is not) until a real versioning scheme exists.

README.md, SECURITY.md and CONTRIBUTING.md exist. `.github/workflows/ci.yml`
runs build/vet/gofmt/test in one job and `golangci-lint` in a separate one
(the two run in parallel, per the linter action's own recommendation), on
every push to `main` and on pull requests — harmless to run on a PR even
though none are accepted (see `CONTRIBUTING.md`), since it costs nothing and
doesn't imply acceptance. `.github/workflows/release.yml` triggers on a `v*`
tag: re-runs the test suite as a safety net (tag pushes don't hit `ci.yml`,
whose trigger is branches-only), cross-compiles the three targets `make
release`'s local equivalent produces (`GOOS=linux`, `amd64`/`arm64`/`armv7`,
`CGO_ENABLED=0`), stamps the version the same way the manual build command
in "Commands" below does, writes `sha256sum` checksums, and publishes a
GitHub Release with `gh release create` — deliberately no third-party
release action, to keep the trust surface of a workflow with
`contents: write` to official actions plus the runner's preinstalled `gh`.

## Commands

No `Makefile` here yet — plain `go` commands:

```bash
go build -o bin/monitor ./cmd/monitor   # build
go vet ./...
gofmt -l .                              # empty output = clean
go test ./... -count=1                  # no MySQL, no server, no network — see "Testing" below
golangci-lint run ./...                 # staticcheck/errcheck/gosec/govet/unused/ineffassign, .golangci.yml
```

Cross-compiling for deployment targets (CGO-free, since `modernc.org/sqlite`
is pure Go):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/monitor-linux-amd64 ./cmd/monitor
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/monitor-linux-arm64 ./cmd/monitor
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o dist/monitor-linux-armv7 ./cmd/monitor
```

`-ldflags "-X github.com/tenpm-software/tenpm-uptime-monitor/internal/version.Version=$(git describe --tags --always --dirty)"`
stamps the version `-version` prints, which the central server also shows
back for each enrolled agent.

## Testing

Entirely hermetic — no MySQL, no real server, no network access required.
The agent's own store is SQLite in a temp file (`internal/migrate` applies
`monitor/migrations/*.sql`), and the sync/enroll/report contract is tested
against a fake HTTP server built only from `model`'s wire types
(`monitor/fakeserver_test.go`, `monitor/contract_test.go`). That fake-server
contract test is the authoritative test of this agent's wire behavior — add
to it, rather than assuming coverage lives elsewhere, whenever you touch
`client.go`, `sync.go`, or `model/api.go`.

## Repo layout

- `cmd/monitor/main.go` — thin entrypoint: flag/env parsing (flags override
  env vars, see `envOr`/`envInt`), opens + migrates the SQLite database, wires
  dependencies, runs until `SIGINT`/`SIGTERM`. `-version` (flag only) prints
  `internal/version.Version` and exits before touching config/logging/the
  database — a check-it-works flag can't have prerequisites of its own.
  Four more flags short-circuit the same way and only need `-db`, not a live
  server: `-test-check FILE` (or `-` for stdin) runs a check definition once
  and exits 0/1/2 (pass/fail/could-not-run) — the offline way to author a
  check against something the server can't reach; `-import-private-check
  FILE` persists a check definition into the local mirror keyed by guid, for
  a check whose definition the server should never see; `-list-checks` and
  `-export-private-checks` print the local mirror as JSON, full content
  included for the checks this agent is the sole source of truth for.
  Env vars / flags: `SERVER_URL`, `ENROLLMENT_TOKEN`, `MONITOR_ID` (only to
  re-adopt an existing monitor after an enrollment reset — the server mints
  ids otherwise), `MONITOR_NAME`, `REGION`/`COUNTRY`/`CITY`, `DB_PATH`
  (default `monitor.db`), `SYNC_INTERVAL_SEC`/`REPORT_INTERVAL_SEC` (default
  45s each), `PROBE_TARGETS`, `MAX_CONCURRENT_CHECKS` (default
  `monitor.DefaultRunnerConcurrency`, 20 — non-positive is fatal at startup,
  not silently coerced), `EGRESS_POLICY` (`open`/`strict`, default `open` —
  an unrecognised value is fatal, since a typo shouldn't silently unrestrict
  a locked-down deployment), `PROXY_URL` (`http://`, `https://`, or
  `socks5://`, optional userinfo — an unsupported scheme is fatal at
  startup), `LOG_LEVEL`.
- `model/` — the wire types shared with the server: `Check`, `Result`,
  `MonitorStatus`, the `/api/*` request/response bodies (`api.go`), and
  header/timestamp encoding helpers. `restricted.go`'s `RestrictedURL`/
  `RestrictedAddr` decide whether a check target is internal — the server
  asks this when classifying a check, this agent asks it before dialling
  under `PolicyStrict`; keeping the logic in this shared package is what lets
  both sides agree on what a shared fleet may run. A check carries several
  optional refinements beyond the basic URL/match rule — see the doc
  comments on `Check.MaxResponseTimeMS`, `DisableRedirects`,
  `StatusCodeOp`/`StatusCodeValue`, `InsecureSkipVerify`,
  `CertExpiryWarnDays`, `InvertResult`/`InvertPassed` — each has a
  `*Exceeded`/`*Acceptable`/`*Passed` sibling method that's the single place
  its rule is evaluated, shared by the daemon runner and `-test-check`.
  `runner.go`'s connectivity gate deliberately sees a check's *raw*,
  pre-invert result — see `Check.InvertPassed`'s doc comment for why.
- `monitor/` — the agent itself:
  - `runner.go` (`Runner`) — runs due checks on their own per-check schedule
    (`schedule.go`, round-robin across a check's assigned monitors, driven by
    `Check.MonitorCount`/`MonitorRank` from the sync delta) against a
    `Checker`: `HTTPChecker` (http/https), `TCPChecker` (raw connect +
    optional banner match), `TLSChecker` (bare TLS handshake, matches a
    certificate summary rather than a banner), `SchemeChecker` (dispatches by
    URL scheme).
  - `registry.go` — `RegisterChecker(scheme, factory)`: how an importer of
    this package adds a check type at compile time (`database/sql` driver
    style; panics on a built-in/duplicate/malformed scheme). A no-op under
    `PolicyStrict` — the scheme allowlist refuses an unregistered scheme
    before dispatch ever reaches it.
  - `egress.go` (`Policy`) — what this agent may connect to.
    `PolicyOpen` (the default) does nothing: an agent on your own hardware
    reaching your own LAN is the product working. `PolicyStrict` is for a
    fleet run on shared or third-party infrastructure, where a
    customer-supplied target could otherwise probe it: only `http`/`https`/
    `tcp` (whatever `model.allowedSchemes` covers), no private/loopback/
    link-local/CGNAT/NAT64/mapped address, resolved and re-checked
    address-by-address (not checked-then-dialled-by-name, which DNS
    rebinding would defeat), with every address `Unmap()`ed first so
    `::ffff:169.254.169.254` can't sail through as "an ordinary IPv6
    address." `pinnedDialer` backs both `HTTPChecker` and `TCPChecker` — the
    same dial path either way, no second implementation to drift. Selected
    at runtime by `-egress-policy=strict`, never by anything the server
    says: this binary is open source, so a restriction baked in here
    protects nobody — the boundary has to live in how a fleet operator
    launches their own instances.
  - `gate.go` (`ConnectivityGate`) — dials independent anycast resolvers to
    tell "this box lost the internet" apart from "the target is actually
    down." `probeOverride` (wired from `agent.go` when `Config.ProxyURL` is
    set) swaps that for an authenticated `GET /api/ping` through the same
    proxied client, since the anycast fanout means nothing from inside a
    network with no direct route out.
  - `proxy.go` (`ParseProxyURL`) — an optional proxy for this agent's own
    traffic to the central server (enroll/sync/report/status, plus the
    connectivity probe) — never for the checks it runs, which always dial
    targets directly regardless of this setting. A deliberately separate
    mechanism from `egress.go`: a private monitor can have direct access to
    what it monitors but no direct route to the outside world.
  - `sync.go` (`Syncer`) — periodically pulls the check-set delta and applies
    it to the local mirror; `reporter.go`/`client.go` buffer and upload
    results/status, tolerating disconnects.
  - `store.go` — local SQLite persistence. Its upsert logic is what keeps a
    private-definition check's content (loaded via `-import-private-check`)
    from being clobbered by an ordinary sync, and vice versa — see the doc
    comments on `ApplyChecksDelta` and `ImportPrivateCheck` before touching
    either; the two have to stay in lockstep on which columns each one is and
    isn't allowed to overwrite.
  - `testcheck.go` — the shared implementation behind `-test-check` and
    `-import-private-check`'s file parsing (`ParseCheckDefinitions`, one
    object or the array form). Runs through the exact same `SchemeChecker`
    and `Policy` the daemon uses, so a pass here is a pass in production and
    a refusal under `PolicyStrict` here is a refusal there too.
- `internal/migrate` — `Open`/`Apply`: the ~40-line embedded-`.sql` migration
  runner for the agent's own SQLite database, tracked in a
  `schema_migrations` table.
- `internal/version` — `Version`, stamped by `-ldflags -X` at release build
  time, `"dev"` otherwise.

## Extensions (custom check types)

Adding a new check type (say, a MySQL login check) only needs a new
`Checker` here, registered via `RegisterChecker` — the server needs almost
nothing, since a check it can't validate is exactly what a
**private-definition check** is for (a name and guid on the server, the real
definition loaded locally via `-import-private-check`, only the pass/fail
verdict ever reported back — see the README). `plugin`-based dynamic
loading was ruled out (needs cgo, identical toolchains, no Windows);
compile-time registration is the model until there's a real need for
something more dynamic, at which point an exec-style checker (a command
whose exit code and output are the result) is next in line, and WASM after
that only if untrusted third-party plugins become an actual requirement.
