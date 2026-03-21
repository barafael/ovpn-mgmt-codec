//! Conformance tests for `>PASSWORD:` management notifications.
//!
//! These notifications are sent by OpenVPN when `--management-query-passwords`
//! is enabled and the client needs credentials. The management client must
//! supply them via `username` and `password` commands.
//!
//! # Prerequisites
//!
//! The `openvpn-client-password` Docker container (port 7508) with its own
//! management interface and `--management-query-passwords`, plus the
//! `openvpn-server` container (port 7506) which must have hold released so
//! the VPN server is accepting connections.
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

/// Connect to a management interface, authenticate, and consume banner + hold.
async fn connect_and_auth(addr: &str) -> Framed<TcpStream, OvpnCodec> {
    let stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot connect to {addr}: {e}"));
    let mut framed = Framed::new(stream, OvpnCodec::new());

    let msg = recv(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt), "expected password prompt, got {msg:?}");

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
    assert!(matches!(&msg, OvpnMessage::Info(_)), "expected >INFO banner, got {msg:?}");

    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Notification(Notification::Hold { .. })),
        "expected >HOLD notification, got {msg:?}",
    );

    framed
}

// ═════════════════════════════════════════════════════════════════════

/// With `--management-query-passwords` and no `auth-user-pass` file,
/// OpenVPN sends `>PASSWORD:Need 'Auth' username/password` after the
/// TLS handshake when the server asks for credentials.
///
/// This test:
/// 1. Releases hold on the VPN server (port 7506) so it accepts connections
/// 2. Connects to the password-client management (port 7508), releases hold
/// 3. Waits for `>PASSWORD:Need 'Auth' username/password`
/// 4. Supplies credentials via `username "Auth"` + `password "Auth"`
/// 5. Verifies the client proceeds (state transitions)
#[tokio::test]
#[traced_test]
async fn password_need_auth() {
    // The VPN server must be running for the client to reach the auth
    // phase where it needs credentials. The server may be restarting
    // after the lifecycle test's SIGUSR1, so retry the connection.
    let server = timeout(Duration::from_secs(30), async {
        loop {
            match TcpStream::connect(SERVER_ADDR).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    })
    .await
    .expect("server management not reachable within 30s");
    let mut server = Framed::new(server, OvpnCodec::new());

    let msg = recv(&mut server).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt), "expected password prompt, got {msg:?}");
    server
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let msg = recv(&mut server).await;
    assert!(matches!(&msg, OvpnMessage::Success(s) if s.contains("password")));
    let _info = recv(&mut server).await;
    let _hold = recv(&mut server).await;

    send_ok(&mut server, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== server hold released ===");

    // Now connect to the password client and release its hold.
    let mut framed = connect_and_auth(CLIENT_PASSWORD_ADDR).await;
    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== client hold released, waiting for >PASSWORD: ===");

    // The client connects to the server, TLS handshake completes, and
    // the server asks for auth credentials. Since there's no auth-user-pass
    // file, OpenVPN asks the management interface.
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

    // After supplying credentials, the client proceeds with auth.
    // The server has management-client-auth but nobody is approving
    // on port 7506, so the connection won't fully complete — but we
    // should see state transitions showing progress (WAIT, AUTH, etc.).
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

    // Clean up both connections.
    framed.send(OvpnCommand::Exit).await.unwrap();
    server.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== password conformance test complete ===");
}
