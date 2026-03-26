//! Wire-format conformance tests: verify that the codec's encoder
//! produces output that a real OpenVPN management interface accepts.
//!
//! These tests encode typed `OvpnCommand` values via the codec and send
//! the resulting wire bytes to OpenVPN. The goal is to catch spec
//! non-compliance in the encoder — e.g., incorrect quoting, escaping,
//! or field ordering that the codec's own parser wouldn't notice.
//!
//! # What this catches that unit tests don't
//!
//! The proptest `command_encode_parse_roundtrip` verifies that the
//! encoder and parser agree with *each other*. But both could be wrong
//! in the same way. These tests use OpenVPN's own `parse_line()` lexer
//! as the oracle:
//! - <https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c>
//! - <https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt>
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_wire_format -- --test-threads=1
//! docker compose down
//! ```
//!
//! `--test-threads=1` because the management interface is single-client.

#![cfg(feature = "conformance-tests")]

mod common;

use common::{connect_and_auth, recv_response, send_ok};
use futures::SinkExt;
use openvpn_mgmt_codec::*;
use tracing_test::traced_test;

const BASIC_ADDR: &str = "127.0.0.1:7505";

// --- Helpers ---

/// Send a command and assert the response is NOT an ERROR containing
/// a parse/syntax complaint. Contextual errors like "command not
/// allowed" are fine — they prove the wire format was parsed correctly.
///
/// Returns the response for further assertions if needed.
async fn send_and_check_accepted(
    framed: &mut tokio_util::codec::Framed<tokio::net::TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
    label: &str,
) -> OvpnMessage {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    // A syntax/parse error from OpenVPN means our wire format is wrong.
    // Contextual errors ("not in server mode") are acceptable — they
    // prove the command was parsed and dispatched, just not applicable.
    if let OvpnMessage::Error(ref e) = msg {
        assert!(
            !e.contains("unknown command") && !e.contains("parse") && !e.contains("Usage"),
            "{label}: encoder output rejected by OpenVPN: {e:?}",
        );
    }
    msg
}

// --- Tests ---

/// Commands that always produce SUCCESS or MultiLine on the basic
/// management-only instance. These are the simplest to validate.
#[tokio::test]
#[traced_test]
async fn basic_commands_accepted() {
    let mut framed = connect_and_auth(BASIC_ADDR).await;

    // Release hold first so state transitions work.
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;

    // `net` is Windows-only — OpenVPN returns a contextual error on
    // Linux.  Wire-format acceptance is still verified (no syntax error).
    send_and_check_accepted(&mut framed, OvpnCommand::Net, "net").await;

    let cases: Vec<(OvpnCommand, &str)> = vec![
        (OvpnCommand::Version, "version"),
        (OvpnCommand::Help, "help"),
        (OvpnCommand::Pid, "pid"),
        (OvpnCommand::LoadStats, "load-stats"),
        (OvpnCommand::Status(StatusFormat::V1), "status 1"),
        (OvpnCommand::Status(StatusFormat::V2), "status 2"),
        (OvpnCommand::Status(StatusFormat::V3), "status 3"),
        (OvpnCommand::State, "state"),
        (OvpnCommand::StateStream(StreamMode::On), "state on"),
        (OvpnCommand::StateStream(StreamMode::Off), "state off"),
        (OvpnCommand::Log(StreamMode::On), "log on"),
        (OvpnCommand::Log(StreamMode::Off), "log off"),
        (OvpnCommand::Echo(StreamMode::On), "echo on"),
        (OvpnCommand::Echo(StreamMode::Off), "echo off"),
        (OvpnCommand::ByteCount(5), "bytecount 5"),
        (OvpnCommand::ByteCount(0), "bytecount 0"),
        (OvpnCommand::Verb(None), "verb"),
        (OvpnCommand::Verb(Some(4)), "verb 4"),
        (OvpnCommand::Mute(None), "mute"),
        (OvpnCommand::Mute(Some(10)), "mute 10"),
        (
            OvpnCommand::AuthRetry(AuthRetryMode::Interact),
            "auth-retry interact",
        ),
        (
            OvpnCommand::AuthRetry(AuthRetryMode::None),
            "auth-retry none",
        ),
        (OvpnCommand::ForgetPasswords, "forget-passwords"),
        (OvpnCommand::HoldOn, "hold on"),
        (OvpnCommand::HoldQuery, "hold"),
    ];

    for (cmd, label) in cases {
        let msg = send_and_check_accepted(&mut framed, cmd, label).await;
        assert!(
            matches!(&msg, OvpnMessage::Success(_) | OvpnMessage::MultiLine(_)),
            "{label}: expected Success or MultiLine, got {msg:?}",
        );
    }

    framed.send(OvpnCommand::Exit).await.unwrap();
}

// Password wire-format acceptance (Username/Password command encoding)
// is covered by conformance_password.rs, which exercises the same
// encoder path against the same openvpn-client-password container.
// Running both tests in CI against shared single-client management
// interfaces causes state conflicts (hold already released, credentials
// already supplied), so the test lives in one place only.
