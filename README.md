# tenpm Uptime Monitor

[![CI](https://github.com/tenpm-software/tenpm-uptime-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/tenpm-software/tenpm-uptime-monitor/actions/workflows/ci.yml)

The open-source agent behind [tenpm Uptime](https://tenpmuptime.com)'s "bring
your own agent" model: a single, self-contained binary you run on your own
hardware — a spare server, a Raspberry Pi, a NAS — that polls a check
schedule from your tenpm account's central server and reports results back.
The agent is public and auditable on purpose: no telemetry beyond what it's
explicitly configured to check, and nothing here can reach anything but the
server it's pointed at and the targets you told it to check.

Apache-2.0 licensed. The central server it talks to is closed-source; this
repository is the whole of the agent side.

## Install

Prebuilt binaries (Linux amd64/arm64/armv7, CGO-free) are attached to each
[release](https://github.com/tenpm-software/tenpm-uptime-monitor/releases)
once tagged. Until then, build from source:

```bash
git clone https://github.com/tenpm-software/tenpm-uptime-monitor.git
cd tenpm-uptime-monitor
go build -o bin/monitor ./cmd/monitor
```

Requires Go 1.26+. The only non-stdlib dependency that matters at runtime is
`modernc.org/sqlite`, a pure-Go SQLite driver, so the resulting binary is
CGO-free and cross-compiles cleanly:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/monitor-linux-amd64 ./cmd/monitor
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/monitor-linux-arm64 ./cmd/monitor
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o dist/monitor-linux-armv7 ./cmd/monitor
```

## Quickstart

1. In your tenpm account, open **Monitors → Add a monitor**. This gives you
   your server's base URL and mints a one-time enrollment token (shown once —
   the server only ever stores its hash, so if you lose it, mint another).
2. Run the agent:

   ```bash
   ./bin/monitor \
     -server-url https://your-server \
     -enrollment-token <paste from the UI> \
     -name "Sydney home box" \
     -region apac -country AU -city Sydney \
     -db monitor.db
   ```
3. The agent enrolls itself, is assigned an id by the server, and starts
   polling for checks. The enrollment token is only needed for that first
   successful enrollment — after that the agent authenticates with its own
   API key, stored in `-db`.

Losing `-db` means losing that identity: the agent will 401 forever against
its old id. Either re-enroll as a new monitor (drop `-id`, get a fresh id),
or pass `-id <the id shown on the server's Monitors page>` to re-adopt the
old one — refused unless your enrollment token already owns that id.

## Configuration

Every setting is a flag or an env var; a flag always wins when both are set.

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `-server-url` | `SERVER_URL` | — | base URL of the central server |
| `-enrollment-token` | `ENROLLMENT_TOKEN` | — | only needed until the first successful enrollment |
| `-id` | `MONITOR_ID` | — | leave empty to let the server mint one; set to re-adopt an existing monitor, or (platform/shared-fleet tokens only) to choose a fresh id yourself |
| `-name` | `MONITOR_NAME` | — | human-readable name, e.g. `"Sydney home box"` |
| `-region` | `REGION` | — | e.g. `apac` |
| `-country` | `COUNTRY` | — | country code, e.g. `AU` |
| `-city` | `CITY` | — | e.g. `Sydney` |
| `-db` | `DB_PATH` | `monitor.db` | path to this agent's SQLite database |
| `-sync-interval` | `SYNC_INTERVAL_SEC` | `45` | seconds between check-sync polls |
| `-report-interval` | `REPORT_INTERVAL_SEC` | `45` | seconds between result-upload attempts |
| `-probe-targets` | `PROBE_TARGETS` | Cloudflare/Google/Quad9 anycast | comma-separated `host:port` list dialed to verify internet connectivity, distinct from your checks' own targets |
| `-max-concurrent-checks` | `MAX_CONCURRENT_CHECKS` | `20` | checks this agent runs at once; a non-positive value is a fatal startup error, not silently coerced |
| `-egress-policy` | `EGRESS_POLICY` | `open` | see [Egress policy](#egress-policy) below |
| `-proxy-url` | `PROXY_URL` | — | see [Proxying agent traffic](#proxying-agent-traffic) below |
| `-log-level` | `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `-version` | — | — | print the build version and exit; ignores every other flag |

`-server-url`, `-name`, `-region`, `-country`, and `-city` are required for
the daemon to start. `-id` is deliberately not in that list — it is the
server's to mint unless you are re-adopting an existing monitor.

## Testing a check before you enroll

```bash
./bin/monitor -test-check check.json
```

Runs the check(s) in `check.json` (or `-` for stdin) once, through the exact
same checker the daemon uses, and prints what came back — pass/fail/could-not-run
as exit code 0/1/2. No enrollment, no `-db`, no server required. This is how
you author and try a check against something only this machine can reach,
before deciding whether the server needs to know its definition at all.

## Private-definition checks

Some checks — one that scripts a credential-guessing request, say, or simply
targets something you don't want the server to know the shape of — can have
their definition live only on the agent(s) that run them. The server holds
just a name and a pass/fail verdict.

```bash
./bin/monitor -import-private-check check.json -db monitor.db
```

Loads the definition(s) in `check.json` into this agent's local database,
keyed by the guid the server already assigned it (export it from the server
first — this flag has nothing to attach a fresh definition to). Needs `-db`
but no server and no enrollment.

```bash
./bin/monitor -list-checks -db monitor.db              # every check this agent mirrors, full content
./bin/monitor -export-private-checks -db monitor.db     # only the ones this agent is the sole source of truth for
```

Both print JSON in the same shape `-import-private-check` reads back — useful
as a backup or an audit trail of what's actually being checked.

## Egress policy

```bash
./bin/monitor -egress-policy strict
```

`open` (the default) does nothing: an agent on your own hardware reaching
your own LAN is the product working as intended. `strict` is for a fleet run
on shared or third-party infrastructure, where a check definition someone
else supplied could otherwise be used to probe your network: only
`http`/`https`/`tcp` targets, no private, loopback, link-local, CGNAT, NAT64,
or IPv4-mapped address — checked address-by-address after DNS resolution
(not resolved once and dialed by name, which a rebinding attack would
defeat).

This is a runtime flag, not something the server can turn on remotely. That's
deliberate: this binary is open source, so a restriction compiled into it
protects nobody who can just build it without that restriction. If you
operate a fleet other people's checks run on, `-egress-policy=strict` is
yours to set when you launch it.

## Proxying agent traffic

```bash
./bin/monitor -proxy-url socks5://user:pass@proxy.example:1080
```

Proxies this agent's own traffic to the central server (enroll, sync,
report, and its connectivity probe) — never the checks it runs, which always
dial their targets directly regardless of this setting. Useful when this box
has a direct route to what it monitors but not to the outside world.
`http://`, `https://`, and `socks5://` are all supported; an unrecognized
scheme is a fatal startup error rather than a silent no-op.

## Extending: custom check types

Check types are compiled in and dispatched by URL scheme. Adding one (say, a
`mysql://` login check) means writing a `monitor.Checker` and registering it:

```go
import "github.com/tenpm-software/tenpm-uptime-monitor/monitor"

func init() {
    monitor.RegisterChecker("mysql", newMySQLChecker)
}
```

in your own small `main.go` that imports this repo's `monitor` package
instead of using the prebuilt binary. See `monitor/registry.go` for the
factory signature. A scheme the server doesn't recognize is exactly what a
[private-definition check](#private-definition-checks) is for — the server
never needs to validate it.

## Development

```bash
go build -o bin/monitor ./cmd/monitor
go vet ./...
gofmt -l .                # empty output = clean
go test ./... -count=1    # hermetic: no MySQL, no real server, no network
golangci-lint run ./...
```

The test suite needs nothing external: the agent's own store is SQLite in a
temp file, and the sync/enroll/report contract is tested against a fake HTTP
server built only from this repo's own wire types (`monitor/fakeserver_test.go`,
`monitor/contract_test.go`).

This repo isn't currently open to outside pull requests — see
[CONTRIBUTING.md](CONTRIBUTING.md) for what kind of feedback we do want, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE).
