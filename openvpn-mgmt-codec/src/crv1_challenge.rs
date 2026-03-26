//! Builder for outgoing CRV1 dynamic-challenge strings.
//!
//! When an OpenVPN server plugin wants to issue a dynamic challenge to a
//! connecting client, it sets the `client_reason` field of a
//! [`ClientDeny`](crate::ClientDeny) to a CRV1-encoded string.  The wire
//! format is:
//!
//! ```text
//! CRV1:{flags}:{state_id_b64}:{username_b64}:{challenge_text}
//! ```
//!
//! where `state_id` and `username` are base64-encoded.  This module
//! provides [`Crv1Challenge`], a typed builder that assembles the string
//! correctly.
//!
//! # Example
//!
//! ```
//! use openvpn_mgmt_codec::{ClientDeny, Crv1Challenge, OvpnCommand};
//!
//! let challenge = Crv1Challenge::builder()
//!     .flags("R,E")
//!     .state_id("session-abc-123")
//!     .username("jdoe")
//!     .challenge_text("Enter your OTP code")
//!     .build();
//!
//! let deny = ClientDeny::builder()
//!     .cid(42)
//!     .kid(0)
//!     .reason("pending MFA")
//!     .client_reason(challenge.to_string())
//!     .build();
//!
//! let cmd = OvpnCommand::ClientDeny(deny);
//! ```

use base64::Engine;
use std::fmt;

/// A CRV1 dynamic-challenge string for use in
/// [`ClientDeny::client_reason`](crate::ClientDeny::client_reason).
///
/// Use the generated builder for ergonomic construction, then call
/// [`.to_string()`](ToString::to_string) to produce the wire-format
/// `CRV1:…` string.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct Crv1Challenge {
    /// Comma-separated CRV1 flags (e.g. `"R,E"`).
    ///
    /// Common flags:
    /// - `R` — the response must be sent back to the server (required)
    /// - `E` — echo the response as the user types
    #[builder(into)]
    pub flags: String,

    /// Opaque state identifier for the auth backend (will be
    /// base64-encoded on the wire).
    #[builder(into)]
    pub state_id: String,

    /// Username (will be base64-encoded on the wire).
    #[builder(into)]
    pub username: String,

    /// Challenge text presented to the user (sent in clear text).
    #[builder(into)]
    pub challenge_text: String,
}

impl fmt::Display for Crv1Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let engine = base64::engine::general_purpose::STANDARD;
        write!(
            f,
            "CRV1:{}:{}:{}:{}",
            self.flags,
            engine.encode(&self.state_id),
            engine.encode(&self.username),
            self.challenge_text,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_produces_valid_crv1_string() {
        let challenge = Crv1Challenge::builder()
            .flags("R,E")
            .state_id("session-123")
            .username("jdoe")
            .challenge_text("Enter OTP")
            .build();

        let wire = challenge.to_string();

        assert!(wire.starts_with("CRV1:R,E:"));
        assert!(wire.ends_with(":Enter OTP"));

        // Verify base64 segments decode correctly.
        let parts: Vec<&str> = wire.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "CRV1");
        assert_eq!(parts[1], "R,E");

        let engine = base64::engine::general_purpose::STANDARD;
        let state_id = engine.decode(parts[2]).expect("valid base64");
        assert_eq!(state_id, b"session-123");

        let username = engine.decode(parts[3]).expect("valid base64");
        assert_eq!(username, b"jdoe");

        assert_eq!(parts[4], "Enter OTP");
    }

    #[test]
    fn empty_fields() {
        let challenge = Crv1Challenge::builder()
            .flags("")
            .state_id("")
            .username("")
            .challenge_text("")
            .build();

        let wire = challenge.to_string();
        // Empty strings base64-encode to empty strings.
        assert_eq!(wire, "CRV1::::");
    }

    #[test]
    fn roundtrip_with_special_characters() {
        let challenge = Crv1Challenge::builder()
            .flags("R")
            .state_id("id with spaces & symbols!")
            .username("user@example.com")
            .challenge_text("Enter your PIN:")
            .build();

        let wire = challenge.to_string();
        let parts: Vec<&str> = wire.splitn(5, ':').collect();

        let engine = base64::engine::general_purpose::STANDARD;
        let state_id = String::from_utf8(engine.decode(parts[2]).unwrap()).unwrap();
        assert_eq!(state_id, "id with spaces & symbols!");

        let username = String::from_utf8(engine.decode(parts[3]).unwrap()).unwrap();
        assert_eq!(username, "user@example.com");
    }
}
