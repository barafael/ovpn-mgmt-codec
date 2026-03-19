/// A parsed real-time notification from OpenVPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// A multi-line `>CLIENT:` notification (CONNECT, REAUTH, ESTABLISHED,
    /// DISCONNECT). The header and all ENV key=value pairs are accumulated
    /// into a single struct before this is emitted.
    Client {
        /// Sub-type: `"CONNECT"`, `"REAUTH"`, `"ESTABLISHED"`, `"DISCONNECT"`.
        event: String,
        /// Everything after the event keyword on the header line (CID, KID, etc.).
        header_args: String,
        /// Accumulated ENV pairs, in order. Each `>CLIENT:ENV,key=val` line
        /// becomes one `(key, val)` entry. The terminating `>CLIENT:ENV,END`
        /// is consumed but not included.
        env: Vec<(String, String)>,
    },

    /// A single-line `>CLIENT:ADDRESS` notification.
    ClientAddress {
        cid: String,
        addr: String,
        primary: String,
    },

    /// Any other single-line notification: `>STATE:...`, `>BYTECOUNT:...`,
    /// `>LOG:...`, `>HOLD:...`, `>PASSWORD:...`, `>ECHO:...`, `>FATAL:...`,
    /// `>NEED-OK:...`, `>NEED-STR:...`, `>RSA_SIGN:...`, `>REMOTE:...`,
    /// `>PROXY:...`, `>BYTECOUNT_CLI:...`, etc.
    Simple {
        /// The notification type keyword (e.g. `"STATE"`, `"BYTECOUNT"`).
        kind: String,
        /// Everything after the first colon.
        payload: String,
    },
}

/// A fully decoded message from the OpenVPN management interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OvpnMessage {
    /// A success response: `SUCCESS: [text]`.
    Success(String),

    /// An error response: `ERROR: [text]`.
    Error(String),

    /// A multi-line response block (from `status`, `version`, `help`, etc.).
    /// The terminating `END` line is consumed but not included.
    MultiLine(Vec<String>),

    /// A single non-SUCCESS/ERROR value line (from bare `hold`, bare `state`,
    /// or `pkcs11-id-get`).
    SingleValue(String),

    /// A real-time notification, either single-line or accumulated multi-line.
    Notification(Notification),

    /// The `>INFO:` banner sent when the management socket first connects.
    /// Technically a notification, but surfaced separately since it's always
    /// the first thing you see and is useful for version detection.
    Info(String),

    /// A line that could not be classified into any known message type.
    /// Contains the raw line and a description of what went wrong.
    Unrecognized {
        line: String,
        kind: crate::unrecognized::UnrecognizedKind,
    },
}
