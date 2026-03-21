use std::fmt;

/// The sub-type of a `>CLIENT:` notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A new client is connecting (`>CLIENT:CONNECT`).
    Connect,

    /// An existing client is re-authenticating (`>CLIENT:REAUTH`).
    Reauth,

    /// A client connection has been fully established (`>CLIENT:ESTABLISHED`).
    Established,

    /// A client has disconnected (`>CLIENT:DISCONNECT`).
    Disconnect,

    /// A client challenge-response (`>CLIENT:CR_RESPONSE,{CID},{KID},{base64}`).
    ///
    /// The base64-encoded response is carried inline because it appears as
    /// the third comma-separated field on the header line (after CID and KID),
    /// not in the ENV block. Both cedws/openvpn-mgmt-go and
    /// jkroepke/openvpn-auth-oauth2 handle this as a distinct event type.
    CrResponse(String),

    /// An unrecognized event type (forward compatibility).
    Custom(String),
}

impl ClientEvent {
    /// Parse a wire event string into a typed variant.
    ///
    /// Note: `CR_RESPONSE` is handled separately in the codec's CLIENT
    /// parser because it carries an extra trailing field (the base64
    /// response). This method maps it to [`Custom`](Self::Custom) as a
    /// fallback; the codec never calls `parse("CR_RESPONSE")`.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "CONNECT" => Self::Connect,
            "REAUTH" => Self::Reauth,
            "ESTABLISHED" => Self::Established,
            "DISCONNECT" => Self::Disconnect,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for ClientEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("CONNECT"),
            Self::Reauth => f.write_str("REAUTH"),
            Self::Established => f.write_str("ESTABLISHED"),
            Self::Disconnect => f.write_str("DISCONNECT"),
            Self::CrResponse(_) => f.write_str("CR_RESPONSE"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}
