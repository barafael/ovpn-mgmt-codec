//! Server-mode conformance tests against a real OpenVPN instance with
//! `--management-client-auth` and an actual VPN client connecting.
//!
//! All server-mode checks run in a single test function using one
//! management connection. This is necessary because OpenVPN's management
//! interface accepts only one client at a time, and the server container
//! needs time to reset between sessions that we cannot reliably wait for.
//!
//! # Prerequisites
//!
//! Three Docker containers: `openvpn` (basic), `openvpn-server`
//! (server-mode with `--management-client-auth` on port 7506), and
//! `openvpn-client` (auto-connecting VPN client).
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_server
//! docker compose down
//! ```

#![cfg(feature = "conformance-tests")]

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing_test::traced_test;

const SERVER_ADDR: &str = "127.0.0.1:7506";
const MGMT_PASSWORD: &str = "test-password";

/// How long to wait for a message before giving up.
const MSG_TIMEOUT: Duration = Duration::from_secs(120);

// ── Helpers ──────────────────────────────────────────────────────────

/// Receive the next message with a timeout.
async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, framed.next())
        .await
        .expect("timed out waiting for message")
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

/// Receive the next command response, skipping real-time notifications.
async fn recv_response(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    loop {
        let msg = recv(framed).await;
        match &msg {
            OvpnMessage::Notification(Notification::State { .. })
            | OvpnMessage::Notification(Notification::Log { .. })
            | OvpnMessage::Notification(Notification::ByteCount { .. })
            | OvpnMessage::Notification(Notification::ByteCountCli { .. }) => continue,
            _ => return msg,
        }
    }
}

/// Drain messages until we see `>CLIENT:CONNECT`. Returns `(cid, kid)`.
async fn wait_for_client_connect(framed: &mut Framed<TcpStream, OvpnCodec>) -> (u64, u64) {
    loop {
        let msg = recv(framed).await;
        if let OvpnMessage::Notification(Notification::Client {
            event: ClientEvent::Connect,
            cid,
            kid: Some(kid),
            ..
        }) = &msg
        {
            return (*cid, *kid);
        }
    }
}

/// Wait for `>CLIENT:CONNECT` and return its ENV block too.
async fn wait_for_client_connect_with_env(
    framed: &mut Framed<TcpStream, OvpnCodec>,
) -> (u64, u64, Vec<(String, String)>) {
    loop {
        let msg = recv(framed).await;
        if let OvpnMessage::Notification(Notification::Client {
            event: ClientEvent::Connect,
            cid,
            kid: Some(kid),
            env,
        }) = msg
        {
            return (cid, kid, env);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// Single comprehensive server-mode test
// ═════════════════════════════════════════════════════════════════════

/// Exercises the entire server-mode management flow in one connection:
///
/// 1. Connect, authenticate, receive INFO + HOLD
/// 2. Verify CLIENT:CONNECT ENV block has expected keys
/// 3. Approve client with `client-auth` (multi-line config push)
/// 4. Observe CLIENT:ESTABLISHED
/// 5. Query status V1/V2/V3 with real client data
/// 6. Query load-stats — nclients >= 1
/// 7. Observe bytecount notification
/// 8. Kill the client, observe CLIENT:DISCONNECT
/// 9. Wait for client to reconnect (auto-retry)
/// 10. Deny the client, observe CLIENT:DISCONNECT
/// 11. Send SIGUSR1, observe state transitions
/// 12. Exit cleanly
#[tokio::test]
#[traced_test]
async fn server_mode_lifecycle() {
    // ── Connect & authenticate ──────────────────────────────────────
    let stream = TcpStream::connect(SERVER_ADDR)
        .await
        .expect("cannot connect to openvpn-server:7506 — is `docker compose up -d` running?");
    let mut framed = Framed::new(stream, OvpnCodec::new());

    let msg = recv(&mut framed).await;
    assert!(
        matches!(msg, OvpnMessage::PasswordPrompt),
        "expected password prompt, got {msg:?}",
    );

    framed
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("password is correct")),
        "expected auth success, got {msg:?}",
    );

    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Info(_)),
        "expected >INFO banner, got {msg:?}",
    );

    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Notification(Notification::Hold { .. })),
        "expected >HOLD notification, got {msg:?}",
    );
    eprintln!("=== authenticated, in hold mode ===");

    // ── Enable notifications & release hold ─────────────────────────
    framed
        .send(OvpnCommand::StateStream(StreamMode::On))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(&msg, OvpnMessage::Success(_)));

    framed.send(OvpnCommand::ByteCount(2)).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(&msg, OvpnMessage::Success(_)));

    framed.send(OvpnCommand::HoldRelease).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("hold release")),
        "hold release failed: {msg:?}",
    );
    eprintln!("=== hold released, waiting for client ===");

    // ── Wait for CLIENT:CONNECT & verify ENV keys ───────────────────
    let (cid, kid, env) = wait_for_client_connect_with_env(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT cid={cid} kid={kid} env_keys={} ===", env.len());

    let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        keys.iter().any(|k| k.contains("common_name") || k.contains("CN")),
        "ENV should contain common_name or CN, got keys: {keys:?}",
    );
    assert!(
        keys.iter().any(|k| k.contains("untrusted_ip") || k.contains("trusted_ip")),
        "ENV should contain an IP-related key, got keys: {keys:?}",
    );

    // ── Approve with client-auth (multi-line config push) ───────────
    framed
        .send(OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines: vec![
                "push \"route 192.168.1.0 255.255.255.0\"".into(),
                "push \"dhcp-option DNS 10.8.0.1\"".into(),
            ],
        })
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("client-auth")),
        "client-auth with config should succeed, got {msg:?}",
    );

    // ── Wait for CLIENT:ESTABLISHED ─────────────────────────────────
    let established_cid = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Established,
                cid: est_cid,
                ..
            }) = &msg
            {
                return *est_cid;
            }
        }
    })
    .await
    .expect("timed out waiting for CLIENT:ESTABLISHED");
    assert_eq!(established_cid, cid);
    eprintln!("=== CLIENT:ESTABLISHED ===");

    // ── Status with real client data ────────────────────────────────
    framed
        .send(OvpnCommand::Status(StatusFormat::V1))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    let v1_lines = match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine for status 1, got {other:?}"),
    };
    assert!(
        v1_lines.iter().any(|l| l.contains("10.8.0")),
        "status 1 should contain VPN address, got {v1_lines:?}",
    );

    framed
        .send(OvpnCommand::Status(StatusFormat::V2))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    let v2_lines = match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine for status 2, got {other:?}"),
    };
    assert!(
        v2_lines.iter().any(|l| l.contains("CLIENT_LIST")),
        "status 2 should contain CLIENT_LIST, got {v2_lines:?}",
    );

    framed
        .send(OvpnCommand::Status(StatusFormat::V3))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    let v3_lines = match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine for status 3, got {other:?}"),
    };
    assert!(
        v3_lines.iter().any(|l| l.contains("CLIENT_LIST")),
        "status 3 should contain CLIENT_LIST, got {v3_lines:?}",
    );

    // ── Load-stats ──────────────────────────────────────────────────
    framed.send(OvpnCommand::LoadStats).await.unwrap();
    let msg = recv_response(&mut framed).await;
    let payload = match msg {
        OvpnMessage::Success(s) => s,
        other => panic!("expected Success for load-stats, got {other:?}"),
    };
    let stats = openvpn_mgmt_codec::parsed_response::parse_load_stats(&payload)
        .expect("load-stats payload should parse");
    assert!(
        stats.nclients >= 1,
        "should have at least 1 client, got {}",
        stats.nclients,
    );
    eprintln!("=== load-stats: {stats:?} ===");

    // ── Bytecount notification ──────────────────────────────────────
    let saw_bytecount = timeout(Duration::from_secs(10), async {
        loop {
            let msg = recv(&mut framed).await;
            if matches!(
                &msg,
                OvpnMessage::Notification(Notification::ByteCountCli { .. })
                    | OvpnMessage::Notification(Notification::ByteCount { .. })
            ) {
                return msg;
            }
        }
    })
    .await;
    assert!(saw_bytecount.is_ok(), "expected bytecount notification");

    // ── Kill client → CLIENT:DISCONNECT ─────────────────────────────
    framed
        .send(OvpnCommand::ClientKill {
            cid,
            message: None,
        })
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(&msg, OvpnMessage::Success(_)));

    let dc_cid = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Disconnect,
                cid: dc,
                ..
            }) = &msg
            {
                return *dc;
            }
        }
    })
    .await
    .expect("timed out waiting for CLIENT:DISCONNECT");
    assert_eq!(dc_cid, cid);
    eprintln!("=== client killed, waiting for reconnect ===");

    // ── Client reconnects → deny ────────────────────────────────────
    let (cid2, kid2) = wait_for_client_connect(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT (reconnect) cid={cid2} kid={kid2} ===");

    framed
        .send(OvpnCommand::ClientDeny {
            cid: cid2,
            kid: kid2,
            reason: "conformance-test-deny".into(),
            client_reason: Some("denied by test".into()),
        })
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("client-deny")),
        "client-deny should succeed, got {msg:?}",
    );

    let dc_cid2 = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Disconnect,
                cid: dc,
                ..
            }) = &msg
            {
                return *dc;
            }
        }
    })
    .await
    .expect("timed out waiting for CLIENT:DISCONNECT after deny");
    assert_eq!(dc_cid2, cid2);
    eprintln!("=== client denied ===");

    // ── Signal SIGUSR1 → state transitions ──────────────────────────
    framed
        .send(OvpnCommand::Signal(Signal::SigUsr1))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(_)),
        "signal SIGUSR1 should succeed, got {msg:?}",
    );

    let mut states = Vec::new();
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            let msg = recv(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State { name, .. }) = msg {
                states.push(name);
            }
        }
    })
    .await;
    assert!(
        !states.is_empty(),
        "should observe state transitions after SIGUSR1",
    );
    eprintln!("=== SIGUSR1 states: {states:?} ===");

    // ── Clean exit ──────────────────────────────────────────────────
    framed.send(OvpnCommand::Exit).await.unwrap();
    let result = framed.next().await;
    assert!(result.is_none(), "stream should end after exit");
    eprintln!("=== server lifecycle test complete ===");
}
