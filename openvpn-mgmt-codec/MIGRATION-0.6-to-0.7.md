# Migrating from 0.6.0 to 0.7.0

## Breaking changes

### `CommandParseError::Syntax(String)` replaced with structured variants

The catch-all `Syntax(String)` variant is gone. Replace match arms with the
three new variants:

```rust
// 0.6
CommandParseError::Syntax(msg) => ...,

// 0.7
CommandParseError::MissingArgs(hint) => ...,
CommandParseError::InvalidNumber { field, input } => ...,
CommandParseError::InvalidChoice { field, input, hint } => ...,
```

### `OvpnCommand::ClientDeny` is now a newtype variant

The inline struct fields were extracted into a dedicated `ClientDeny` type with
builder support.

```rust
// 0.6
OvpnCommand::ClientDeny { cid, kid, reason, client_reason }

// 0.7
use openvpn_mgmt_codec::ClientDeny;

OvpnCommand::ClientDeny(ClientDeny { cid, kid, reason, client_reason })

// or construct with the builder:
OvpnCommand::ClientDeny(
    ClientDeny::builder()
        .cid(42)
        .kid(0)
        .reason("policy violation")
        .client_reason("Your session was denied.")
        .build()
)
```

### `Notification::Client::env` changed from `Vec<(String, String)>` to `BTreeMap<String, String>`

```rust
// 0.6
Notification::Client { env, .. } => {
    for (key, value) in &env { ... }
}

// 0.7
use std::collections::BTreeMap;

Notification::Client { env, .. } => {
    for (key, value) in &env { ... }  // iterates in sorted key order
    let cn = env.get("common_name");  // direct lookup now available
}
```

Duplicate keys now collapse (last value wins) instead of appearing twice.

### `RemoteEntryRange::Range` field `to` renamed to `end`

```rust
// 0.6
RemoteEntryRange::Range { from, to }

// 0.7
RemoteEntryRange::Range { from, end }
```

### `stream::classify` free function replaced with `ClassifyExt` trait

```rust
// 0.6
use openvpn_mgmt_codec::stream::{classify, ManagementEvent};
let mut mgmt = raw_stream.map(classify);

// 0.7
use openvpn_mgmt_codec::stream::{ClassifyExt, ManagementEvent};
// or: use openvpn_mgmt_codec::{ClassifyExt, ManagementEvent};
let mut mgmt = raw_stream.classify();
```

### `AuthType::FromStr` compact aliases removed

`"PrivateKey"`, `"HTTPProxy"`, and `"SOCKSProxy"` no longer parse. Only the
spaced forms are accepted: `"Private Key"`, `"HTTP Proxy"`, `"SOCKS Proxy"`.

### `>INFO:` handling split between banner and notifications

Previously every `>INFO:` line produced `OvpnMessage::Info(String)`. Now only
the **first** `>INFO:` (the connection banner) produces `OvpnMessage::Info`.
All subsequent `>INFO:` messages produce
`OvpnMessage::Notification(Notification::Info { message })`.

```rust
// 0.7 — handle both forms
match msg {
    OvpnMessage::Info(banner) => println!("connected: {banner}"),
    OvpnMessage::Notification(Notification::Info { message }) => {
        println!("info: {message}");
    }
    _ => {}
}
```

### Default accumulation limit changed

`AccumulationLimit` for multi-line responses now defaults to `Max(10_000)`
instead of `Unlimited`. Override in `OvpnCodec` if you need unbounded
accumulation.

## New enum variants (exhaustive match update required)

### `OvpnCommand`

| Variant | Wire format |
|---------|------------|
| `SetVersion(u32)` | `version 2` |
| `ClientPendingAuth { cid, kid, extra, timeout }` | `client-pending-auth 42 0 "WEB_AUTH" 300` |
| `CrResponse { response: Redacted }` | `cr-response dGVzdA==` |
| `PkSig { base64_lines }` | multi-line: `pk-sig` / lines / `END` |
| `Certificate { pem_lines }` | multi-line: `certificate` / lines / `END` |

### `Notification`

| Variant | Wire format |
|---------|------------|
| `PkSign { data, algorithm }` | `>PK_SIGN:b64[,algo]` |
| `InfoMsg { extra }` | `>INFOMSG:extra` |
| `NeedCertificate { hint }` | `>NEED-CERTIFICATE:hint` |
| `Info { message }` | `>INFO:msg` (subsequent, not banner) |

### `RemoteAction`

| Variant | Wire format |
|---------|------------|
| `SkipN(u32)` | `remote SKIP 2` (management v3+) |

## New types and modules

### `ClientDeny` ([client_deny](src/client_deny.rs))

Typed struct with `bon::Builder` derive for `client-deny` commands. Re-exported
at the crate root.

### `Crv1Challenge` ([crv1_challenge](src/crv1_challenge.rs))

Builder for outgoing CRV1 dynamic-challenge strings. Produces the
`CRV1:{flags}:{state_id_b64}:{username_b64}:{challenge_text}` wire format.

```rust
use openvpn_mgmt_codec::Crv1Challenge;

let challenge = Crv1Challenge::builder()
    .flags("R,E")
    .state_id("session-42")
    .username("alice")
    .challenge_text("Enter your TOTP code")
    .build();
println!("{challenge}"); // CRV1:R,E:<b64>:<b64>:Enter your TOTP code
```

### Status parsing ([status](src/status.rs))

New module for parsing `status` command responses into typed structs:

```rust
use openvpn_mgmt_codec::{parse_status, parse_client_statistics};

// From an OvpnMessage::MultiLine(lines):
let status = parse_status(&lines)?;
for client in &status.clients {
    println!("{}: {}B in", client.common_name, client.bytes_received);
}

let stats = parse_client_statistics(&lines)?;
println!("connected since: {}", stats.connected_since);
```

Exported types: `StatusResponse`, `ConnectedClient`, `RoutingEntry`,
`ClientStatistics`, `ParseStatusError`.

### Parsed response additions

- `StateEntry` struct and `parse_state_entry()`, `parse_state_history()`,
  `parse_current_state()` for typed `state` response parsing
- `parse_hold()` for `hold` query responses
- `parse_version()` for `version` multi-line responses

### `server_connection_sequence()`

New convenience function alongside the existing `connection_sequence()`, adding
`EnvFilter` for server-mode management clients.

```rust
use openvpn_mgmt_codec::server_connection_sequence;

let cmds = server_connection_sequence(5, 0);
for cmd in cmds {
    sink.send(cmd).await?;
}
```

### `ManagementClient` ([client](src/client.rs))

High-level client that separates command responses from async notifications.
Command methods return parsed responses directly; notifications are forwarded
to a caller-provided `broadcast::Sender<Notification>`.

```rust
use tokio::sync::broadcast;
use openvpn_mgmt_codec::{Notification, ManagementClient, StatusFormat};

let (notification_tx, _) = broadcast::channel::<Notification>(256);
let mut rx = notification_tx.subscribe();
let mut client = ManagementClient::new(framed, notification_tx);

let version = client.version().await?;
let status = client.status(StatusFormat::V3).await?;
client.hold_release().await?;
```

### Timestamp formatting ([timestamp](src/timestamp.rs))

Lightweight UTC timestamp formatting without external dependencies:

```rust
use openvpn_mgmt_codec::timestamp::{format_utc, format_local_style};

assert_eq!(format_utc(1_711_031_400), "2024-03-21T14:30:00Z");
assert_eq!(format_local_style(1_711_031_400), "2024-03-21 14:30:00");
```

### `StreamMode` now derives `Copy`

`StreamMode` is now `Copy`, and gains a `returns_history()` method that
indicates whether the mode produces a multi-line history dump.

## Behavioral changes

- **Command pipelining**: The codec now uses an internal queue for expected
  responses instead of a single slot. Multiple commands can be sent without
  waiting for each response.
- **Quote-aware command parsing**: `FromStr` for `OvpnCommand` now handles
  OpenVPN's double-quoted token syntax with backslash escaping (`\"` -> `"`,
  `\\` -> `\`). This is a correctness fix — auth types with spaces like
  `"Private Key"` now parse correctly.
- **`client-pending-auth` extra length warning**: A `warn!` is emitted when the
  `extra` field exceeds 245 characters (real-world limit from
  openvpn-auth-oauth2).

## New dependencies

- `bon` — builder derives for `ClientDeny` and `Crv1Challenge`
- `base64` — CRV1 challenge encoding
- `futures-core`, `futures-util`, `pin-project-lite` — `ClassifyExt` stream adapter and `ManagementClient`
- `tokio` (sync feature) — `broadcast` channel for `ManagementClient`
