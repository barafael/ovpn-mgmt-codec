# Conformance Testing Details

## What the conformance tests found

Two protocol bugs in the codec, both invisible without a real OpenVPN instance:

### 1. Password prompt has no newline

OpenVPN 2.6 sends `ENTER PASSWORD:` as an interactive prompt — 15 raw bytes,
no `\n`, no `\r\n`. The codec's line-oriented decoder waited forever for a
line terminator that never arrived.

No spec documents this. No other implementation we compared against handles
it. Every test we had — unit, proptest, fixture-based — used
`ENTER PASSWORD:\n` because that's what the line-oriented protocol implies.

**Hex dump from CI:**
```
00000000: 454e 5445 5220 5041 5353 574f 5244 3a    ENTER PASSWORD:
```

**Fix:** detect the prompt in the buffer even without `\n`; skip bare empty
lines outside accumulation contexts to absorb a trailing `\n` from older
versions without producing a spurious `Unrecognized` message.

### 2. Management version header wording changed

OpenVPN 2.6.16 sends `Management Version: 5` instead of
`Management Interface Version: 5` — a silent wording change. The version
parser used exact prefix matching and returned `None`, so any consumer
feature-gating on management version would silently disable features.

**Fix:** fuzzy match any line starting with "management" containing
"version", extract the trailing number. Handles both known formats and
hypothetical future variations.

## Operational details no spec covers

The conformance tests also forced us to understand runtime behaviors that
are absent from `management-notes.txt` and all other documentation:

- **`management-client-auth` requires `auth-user-pass`**: the VPN client
  must send username/password credentials even when using certificate auth.
  Without them, the TLS handshake fails with `Auth Username/Password was
  not provided by peer` and `>CLIENT:CONNECT` is never sent to the
  management interface.

- **`nc -z` healthchecks steal the management slot**: OpenVPN's management
  interface accepts one client at a time. A Docker healthcheck using
  `nc -z` connects every second, and OpenVPN accepts each probe as a
  management client, sends `ENTER PASSWORD:`, then processes the disconnect.
  The real test client's TCP connection sits in the kernel accept queue and
  never gets serviced. Fix: use `pidof openvpn` as the healthcheck.

- **`dev null` is not a real device mode**: the original test config used
  `dev null` (copied from a local test script that happened to work). On
  Alpine Linux, OpenVPN interprets this as a device named "null", can't
  determine TUN vs TAP type, and stalls after opening the management port
  but before entering its event loop. Fix: use `dev tun` with
  `/dev/net/tun` mounted; `management-hold` prevents OpenVPN from touching
  the device until hold is released.

- **`connect-retry` uses exponential backoff**: the default `connect-retry 1`
  doubles the interval on each failure up to 300 seconds. After hold release,
  the client's next retry could be 16+ seconds away, eating into the test
  timeout. Fix: `connect-retry 1 1` (initial=1s, max=1s).

- **Server mode goes silent after hold release if initialization fails**:
  the `hold release` command returns `SUCCESS` even when the subsequent
  initialization (TUN creation, UDP binding) hasn't completed yet. If
  initialization fails silently, the management interface stays connected
  but sends zero notifications — no state transitions, no errors. The only
  way to diagnose this is `verb 9` in the server config and checking
  container logs.

## Test structure

### Basic conformance tests (`conformance.rs`, 18 tests)

Connect to a management-only OpenVPN instance (no tunnel, held mode) on
port 7505. Each test opens its own management connection. Tests run with
`--test-threads=1` because the management interface accepts one client at
a time.

Covers: password auth, version, help, pid, state queries, status V1/V2/V3,
stream toggling (log/echo/state/bytecount on/off), hold release with state
notification, log history, error handling, sequential codec state, clean exit.

### Server-mode conformance test (`conformance_server.rs`, 1 lifecycle test)

Connects to a full server-mode OpenVPN instance (port 7506) with
`--management-client-auth`, a TUN tunnel, and an auto-connecting VPN
client container. Uses a single management connection for the entire
lifecycle because the server container doesn't reliably accept new
management connections after an authenticated session disconnects.

Covers: hold release, `>CLIENT:CONNECT` with ENV block verification
(44 keys including TLS cert info), `client-auth` with config push
(routes + DNS), `>CLIENT:ESTABLISHED`, status V1/V2/V3 with real client
data, `load-stats` with live byte counts, `>BYTECOUNT_CLI` notification,
`client-kill` + `>CLIENT:DISCONNECT`, client auto-reconnect, `client-deny`
+ `>CLIENT:DISCONNECT`, `signal SIGUSR1` state transitions, clean exit.

## Effort

The Docker infrastructure was about half a day. The protocol surprises
took the other half. Most of the debugging time was spent on the password
prompt issue — the symptom (all tests hang at `recv()`) gave no indication
that the data was arriving but missing a newline.
