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
    /// An unrecognized event type (forward compatibility).
    Custom(String),
}

impl ClientEvent {
    /// Parse a wire event string into a typed variant.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "CONNECT" => Self::Connect,
            "REAUTH" => Self::Reauth,
            "ESTABLISHED" => Self::Established,
            "DISCONNECT" => Self::Disconnect,
            other => Self::Custom(other.to_owned()),
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
            Self::Custom(s) => f.write_str(s),
        }
    }
}
