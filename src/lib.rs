//! OpenVPN Management Interface Codec
//!
//! A `tokio_util::codec`-based encoder/decoder for the OpenVPN management
//! interface protocol, as documented at:
//! <https://openvpn.net/community-docs/management-interface.html>
//!
//! # Protocol summary
//!
//! The management interface is a line-oriented text protocol over TCP or
//! Unix domain sockets.
//! The client sends newline-terminated commands, and OpenVPN replies with:
//!
//!   1. Single-line responses: `SUCCESS: [text]` or `ERROR: [text]`
//!   2. Multi-line responses: several lines terminated by a bare `END` line
//!   3. Real-time notifications: lines starting with `>`, e.g. `>STATE:...`
//!      Some notifications (notably `>CLIENT:`) are themselves multi-line,
//!      terminated by `>CLIENT:ENV,END`.
//!
//! # Command parsing (wire format)
//!
//! The management interface uses the same lexer as the OpenVPN config file:
//!   - Whitespace separates parameters
//!   - Double or single quotes can enclose parameters containing whitespace
//!   - Backslash escaping: `\\` → `\`, `\"` → `"`, `\ ` → literal space

pub mod auth;
pub mod codec;
pub mod command;
pub mod kill_target;
pub mod message;
pub mod need_ok;
pub mod proxy_action;
pub mod remote_action;
pub mod signal;
pub mod status_format;
pub mod stream_mode;
pub mod unrecognized;

pub use auth::{AuthRetryMode, AuthType};
pub use codec::OvpnCodec;
pub use command::OvpnCommand;
pub use kill_target::KillTarget;
pub use message::{Notification, OvpnMessage};
pub use need_ok::NeedOkResponse;
pub use proxy_action::ProxyAction;
pub use remote_action::RemoteAction;
pub use signal::Signal;
pub use status_format::StatusFormat;
pub use stream_mode::StreamMode;
pub use unrecognized::UnrecognizedKind;
