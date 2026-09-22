# Security policy

## Reporting a vulnerability

Email **hello@tenpm.com.au** with `[SECURITY]` in the subject. Please include:

- what you found and why it's a vulnerability, not just unexpected behavior;
- steps or a proof of concept to reproduce it;
- the version or commit you tested against (`monitor -version`).

We'll acknowledge your report within 3 business days and aim to have a fix or
a mitigation plan within 90 days of confirming it. We'll credit you in the
release notes unless you'd rather stay anonymous — say so in your report.

Please don't open a public GitHub issue for a suspected vulnerability until
we've had a chance to respond.

## Scope

This repository is the open-source **agent** only: the binary in `cmd/monitor`
and the packages it's built from (`model/`, `monitor/`, `internal/`). In
scope:

- the agent misbehaving toward a target it wasn't told to check (an egress
  policy bypass, a `-egress-policy=strict` restriction that doesn't actually
  hold under some address or scheme);
- the agent leaking data it shouldn't — credentials, a private check's
  definition, another check's result — to the wrong place;
- a crash, resource exhaustion, or code-execution bug reachable from a
  malicious server response, a malicious check target's response, or a
  crafted `-test-check`/`-import-private-check` input file;
- a dependency vulnerability in this module's own `go.sum`.

**Out of scope:**

- the closed-source central server this agent talks to (a separate,
  private codebase — if you found something there, email the same address
  and say so, since it isn't the repo you're looking at);
- the behavior of a check *target* you pointed the agent at yourself —
  the agent doing exactly what you configured it to do to a host you named
  is not a vulnerability in the agent;
- anything that requires local code execution or a compromised host the
  agent already runs on — at that point the agent's own database (API key,
  any imported private check definitions) is only as protected as the
  filesystem permissions you gave it, which is your responsibility to set.

## Supported versions

Pre-1.0: only the latest tagged release and the tip of `main` are supported.
There's no long-term-support branch yet.

## The agent's own threat model, briefly

This is a short, standalone summary for people auditing this repository —
not the private server's full threat model, which lives in the closed
codebase and covers the multi-tenant control plane.

- **No telemetry beyond what you configure.** The agent talks to exactly two
  kinds of endpoint: the central server named by `-server-url` (enroll,
  sync, report results, an optional connectivity probe), and whatever check
  targets are in its synced check set. Nothing else.
- **Two independent dial paths, on purpose.** `-proxy-url` only ever affects
  traffic to the central server. Checks always dial their targets directly,
  regardless of that setting — a private monitor with a direct LAN route to
  what it's checking but no route to the wider internet is a supported,
  intentional case, not an oversight.
- **`-egress-policy` is a launch-time choice, not a built-in restriction.**
  `open` (the default) does nothing, because an agent you run on your own
  hardware reaching your own network is the product working. `strict` exists
  for a fleet where checks may be supplied by someone other than the person
  running the box — no private/loopback/link-local/CGNAT/NAT64/mapped
  address, resolved and re-checked address-by-address rather than
  checked-then-dialed-by-name (which a DNS-rebinding attack between the two
  steps would defeat), with every address unmapped first so an
  IPv4-mapped-IPv6 form of an internal address can't slip past the check.
  Because this binary is open source, the restriction only has teeth when
  *you* choose to launch it that way on infrastructure you don't want
  probed — it protects nobody baked in, since anyone can build a copy
  without it.
- **A check's own outbound request is attacker-reachable by design** — that's
  what a check *is*. `-egress-policy=strict` is the mitigation for running
  other people's check definitions; if you're only ever running checks you
  wrote yourself against targets you chose, `open` is the correct and safe
  default.
- **Private-definition checks keep their content local on purpose.** A
  check imported via `-import-private-check` never leaves this agent's own
  SQLite database — that's the entire point of the feature, for a check
  whose definition (a credential, an internal hostname, a scripted request)
  shouldn't reach the server at all. Protecting that database file — normal
  filesystem permissions, disk encryption if that matters to your threat
  model — is the operator's responsibility; nothing in the agent encrypts
  it at rest.
- **The enrollment token and the agent's own API key are bearer
  credentials.** An enrollment token is meant to be used once and is only
  ever needed until the first successful enrollment; after that, treat the
  `-db` file as holding a live credential and protect it accordingly.
