//! Conformance tests for `>PASSWORD:` management notifications.
//!
//! These notifications are sent by OpenVPN when `--management-query-passwords`
//! is enabled and the client needs credentials. The management client must
//! supply them via `username` and `password` commands.
//!
//! # Prerequisites
//!
//! The `openvpn-client-password` Docker container (port 7508) with its own
//! management interface and `--management-query-passwords`.
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

async fn send_ok(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
    expected: &str,
) {
    framed.send(cmd).await.unwrap();
    loop {
        let msg = recv(framed).await;
        match &msg {
            OvpnMessage::Notification(_) => continue,
            _ => {
                assert!(
                    matches!(&msg, OvpnMessage::Success(s) if s.contains(expected)),
                    "expected Success containing {expected:?}, got {msg:?}",
                );
                return;
            }
        }
    }
}

async fn connect_client_mgmt() -> Framed<TcpStream, OvpnCodec> {
    let stream = TcpStream::connect(CLIENT_PASSWORD_ADDR)
        .await
        .expect("cannot connect to client-password:7508 — is `docker compose up -d` running?");
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

/// After hold release, a client with `--management-query-passwords` (and
/// no `auth-user-pass` file) sends `>PASSWORD:Need 'Auth' username/password`
/// to request credentials from the management interface.
///
/// This test:
/// 1. Connects to the client's management interface, authenticates
/// 2. Enables state notifications, releases hold
/// 3. Waits for `>PASSWORD:Need 'Auth' username/password`
/// 4. Supplies credentials via `username "Auth"` + `password "Auth"`
/// 5. Verifies the client proceeds (state transitions toward connecting)
#[tokio::test]
#[traced_test]
async fn password_need_auth() {
    let mut framed = connect_client_mgmt().await;
    eprintln!("=== authenticated to client-password management ===");

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for >PASSWORD: ===");

    // After hold release, the client tries to connect. Since there's no
    // auth-user-pass file, it asks the management interface for credentials.
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
        matches!(&pw_notification, PasswordNotification::NeedAuth { auth_type } if *auth_type == AuthType::Auth),
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

    // After supplying credentials, the client should proceed to connect.
    // Watch for state transitions indicating progress. The server might
    // not approve (management-client-auth with no one connected), but
    // we should at least see WAIT/AUTH states.
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

    // Clean exit.
    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== password conformance test complete ===");
}
