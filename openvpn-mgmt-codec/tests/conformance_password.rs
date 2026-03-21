//! Conformance tests for `>PASSWORD:` management notifications.
//!
//! These notifications are sent by OpenVPN when `--management-query-passwords`
//! is enabled and the client needs credentials. The management client must
//! supply them via `username` and `password` commands.
//!
//! # Prerequisites
//!
//! The `openvpn-client-password` Docker container (port 7508) with
//! `--management-query-passwords`, plus `openvpn-server` (port 7506).
//! The server has `management-client-auth`, so this test must also approve
//! the client on the server side for the TLS handshake to complete.
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_password
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
const CLIENT_PASSWORD_ADDR: &str = "127.0.0.1:7508";
const MGMT_PASSWORD: &str = "test-password";
const MSG_TIMEOUT: Duration = Duration::from_secs(120);

// ── Helpers ──────────────────────────────────────────────────────────

async fn recv_raw(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    framed
        .next()
        .await
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, recv_raw(framed))
        .await
        .expect("timed out waiting for message")
}

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

async fn send_ok(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
    expected: &str,
) {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains(expected)),
        "expected Success containing {expected:?}, got {msg:?}",
    );
}

// ═════════════════════════════════════════════════════════════════════

/// With `--management-query-passwords` and no `auth-user-pass` file,
/// OpenVPN sends `>PASSWORD:Need 'Auth' username/password` after the
/// TLS handshake when the server asks for credentials.
///
/// The server has `management-client-auth`, so a background task
/// auto-approves the client on port 7506 while the main task handles
/// the password flow on port 7508.
#[tokio::test]
#[traced_test]
async fn password_need_auth() {
    // ── Set up server: connect, release hold, auto-approve clients ──
    let server_stream = timeout(Duration::from_secs(30), async {
        loop {
            match TcpStream::connect(SERVER_ADDR).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    })
    .await
    .expect("server management not reachable within 30s");
    let mut server = Framed::new(server_stream, OvpnCodec::new());

    // Authenticate to server management.
    let msg = recv(&mut server).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));
    server
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let _success = recv(&mut server).await;
    let _info = recv(&mut server).await;
    let _hold = recv(&mut server).await;

    send_ok(&mut server, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== server hold released ===");

    // Spawn a task that auto-approves any CLIENT:CONNECT on the server.
    tokio::spawn(async move {
        loop {
            let msg = match timeout(Duration::from_secs(60), server.next()).await {
                Ok(Some(Ok(msg))) => msg,
                _ => return,
            };
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Connect,
                cid,
                kid: Some(kid),
                ..
            }) = msg
            {
                eprintln!("=== server: auto-approving CLIENT:CONNECT cid={cid} kid={kid} ===");
                let _ = server
                    .send(OvpnCommand::ClientAuthNt { cid, kid })
                    .await;
            }
        }
    });

    // ── Set up client: connect, release hold, wait for >PASSWORD: ───
    let client_stream = TcpStream::connect(CLIENT_PASSWORD_ADDR)
        .await
        .expect("cannot connect to client-password:7508");
    let mut framed = Framed::new(client_stream, OvpnCodec::new());

    let msg = recv(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));
    framed
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let _success = recv(&mut framed).await;
    let _info = recv(&mut framed).await;
    let _hold = recv(&mut framed).await;

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== client hold released, waiting for >PASSWORD: ===");

    // The client connects to the server. The spawned task approves the
    // CLIENT:CONNECT. Then the server asks for auth credentials, and
    // since there's no auth-user-pass file, the client sends
    // >PASSWORD:Need 'Auth' to its management interface.
    let pw_notification = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Password(ref pw)) = msg {
                return pw.clone();
            }
        }
    })
    .await
    .expect("timed out waiting for >PASSWORD: notification");

    eprintln!("=== >PASSWORD: {pw_notification:?} ===");
    assert!(
        matches!(
            &pw_notification,
            PasswordNotification::NeedAuth { auth_type } if *auth_type == AuthType::Auth
        ),
        "expected NeedAuth with AuthType::Auth, got {pw_notification:?}",
    );

    // Supply credentials via management.
    framed
        .send(OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: Redacted::new("testuser"),
        })
        .await
        .unwrap();
    framed
        .send(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: Redacted::new("testpass"),
        })
        .await
        .unwrap();
    eprintln!("=== credentials supplied ===");

    // After supplying credentials, the client should proceed.
    let mut states = Vec::new();
    let _ = timeout(Duration::from_secs(15), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State { name, .. }) = msg {
                states.push(name);
            }
        }
    })
    .await;

    assert!(
        !states.is_empty(),
        "should observe state transitions after supplying credentials",
    );
    eprintln!("=== states after credentials: {states:?} ===");

    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== password conformance test complete ===");
}
