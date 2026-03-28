//! High-level management client with notification dispatch.
//!
//! [`ManagementClient`] wraps a `Framed<T, OvpnCodec>` transport and splits
//! the multiplexed stream into two independent channels:
//!
//! - **Command methods** (`version`, `status`, `hold_release`, etc.) send a
//!   command and return its response directly.
//! - **Notifications** are forwarded to a [`tokio::sync::broadcast`] channel
//!   that any number of subscribers can consume independently.
//!
//! # Example
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio::sync::broadcast;
//! use tokio_util::codec::Framed;
//! use openvpn_mgmt_codec::{Notification, OvpnCodec, StatusFormat};
//! use openvpn_mgmt_codec::client::ManagementClient;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//!
//! // Create the broadcast channel — you control capacity and lifetime.
//! let (notification_tx, _) = broadcast::channel::<Notification>(256);
//! let mut rx = notification_tx.subscribe();
//! let mut client = ManagementClient::new(framed, notification_tx);
//!
//! // Spawn a notification consumer
//! tokio::spawn(async move {
//!     while let Ok(notif) = rx.recv().await {
//!         println!("notification: {notif:?}");
//!     }
//! });
//!
//! // Commands return their response directly
//! let version = client.version().await?;
//! println!("management version: {:?}", version.management_version());
//!
//! let status = client.status(StatusFormat::V3).await?;
//! client.hold_release().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Extracting the transport
//!
//! Call [`ManagementClient::into_framed`] to recover the underlying
//! `Framed<T, OvpnCodec>` when you need raw access or want to drop back
//! to the low-level stream API.

use std::io;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tokio_util::codec::Framed;

use crate::auth::{AuthRetryMode, AuthType};
use crate::client_deny::ClientDeny;
use crate::codec::OvpnCodec;
use crate::command::{OvpnCommand, RemoteEntryRange};
use crate::kill_target::KillTarget;
use crate::message::{Notification, OvpnMessage};
use crate::need_ok::NeedOkResponse;
use crate::parsed_response::{self, LoadStats, StateEntry};
use crate::proxy_action::ProxyAction;
use crate::redacted::Redacted;
use crate::remote_action::RemoteAction;
use crate::signal::Signal;
use crate::status::{self, ClientStatistics, StatusResponse};
use crate::status_format::StatusFormat;
use crate::stream_mode::StreamMode;
use crate::version_info::VersionInfo;

/// Errors returned by [`ManagementClient`] command methods.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The transport returned an I/O error.
    #[error("transport error: {0}")]
    Io(#[from] io::Error),

    /// The connection was closed before a response arrived.
    #[error("connection closed while awaiting response")]
    ConnectionClosed,

    /// The server returned `ERROR: {0}`.
    #[error("server error: {0}")]
    ServerError(String),

    /// The response type did not match what the command expected.
    #[error("unexpected response: {0:?}")]
    UnexpectedResponse(OvpnMessage),

    /// A `SUCCESS:` payload could not be parsed.
    #[error("response parse error: {0}")]
    ParseResponse(#[from] parsed_response::ParseResponseError),

    /// A `status` response could not be parsed.
    #[error("status parse error: {0}")]
    ParseStatus(#[from] status::ParseStatusError),
}

/// A high-level client for the OpenVPN management interface.
///
/// See the [module documentation](self) for usage examples.
pub struct ManagementClient<T> {
    framed: Framed<T, OvpnCodec>,
    notification_tx: broadcast::Sender<Notification>,
}

impl<T> ManagementClient<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Wrap a framed transport with an existing broadcast sender for
    /// notification dispatch.
    ///
    /// The caller creates the [`broadcast::channel`] and passes the sender
    /// here. This gives full control over channel capacity and lifetime.
    /// Call [`broadcast::Sender::subscribe`] on your copy of the sender to
    /// create receivers — multiple independent subscribers are supported.
    pub fn new(
        framed: Framed<T, OvpnCodec>,
        notification_tx: broadcast::Sender<Notification>,
    ) -> Self {
        Self {
            framed,
            notification_tx,
        }
    }

    /// Recover the underlying framed transport.
    pub fn into_framed(self) -> Framed<T, OvpnCodec> {
        self.framed
    }

    // --- Internal helpers ---

    /// Read frames until a non-notification message arrives. Interleaved
    /// notifications are forwarded to the broadcast channel.
    async fn recv_response(&mut self) -> Result<OvpnMessage, ClientError> {
        loop {
            let msg = self
                .framed
                .next()
                .await
                .ok_or(ClientError::ConnectionClosed)??;

            match msg {
                OvpnMessage::Notification(notification) => {
                    // No active receivers is fine — notifications are best-effort.
                    self.notification_tx
                        .send(notification)
                        .inspect_err(|error| {
                            tracing::debug!(%error, "no notification subscribers");
                        })
                        .ok();
                }
                other => return Ok(other),
            }
        }
    }

    /// Send a command and read frames until a non-notification response
    /// arrives.
    async fn send_and_recv(&mut self, cmd: OvpnCommand) -> Result<OvpnMessage, ClientError> {
        self.framed.send(cmd).await?;
        self.recv_response().await
    }

    /// Send a command that expects `SUCCESS:` and return the payload string.
    async fn send_expect_success(&mut self, cmd: OvpnCommand) -> Result<String, ClientError> {
        match self.send_and_recv(cmd).await? {
            OvpnMessage::Success(payload) => Ok(payload),
            OvpnMessage::Error(msg) => Err(ClientError::ServerError(msg)),
            other => Err(ClientError::UnexpectedResponse(other)),
        }
    }

    /// Send a command that expects a multi-line response.
    async fn send_expect_multi_line(
        &mut self,
        cmd: OvpnCommand,
    ) -> Result<Vec<String>, ClientError> {
        match self.send_and_recv(cmd).await? {
            OvpnMessage::MultiLine(lines) => Ok(lines),
            OvpnMessage::Error(msg) => Err(ClientError::ServerError(msg)),
            other => Err(ClientError::UnexpectedResponse(other)),
        }
    }

    /// Send a command that expects `SUCCESS:` and discard the payload.
    async fn send_expect_ok(&mut self, cmd: OvpnCommand) -> Result<(), ClientError> {
        self.send_expect_success(cmd).await?;
        Ok(())
    }

    /// Send a stream-mode command (`log`, `state`, `echo`).
    ///
    /// History-returning modes produce `Some(lines)`, on/off modes
    /// produce `None`.
    async fn send_stream_command(
        &mut self,
        mode: StreamMode,
        cmd: OvpnCommand,
    ) -> Result<Option<Vec<String>>, ClientError> {
        if mode.returns_history() {
            Ok(Some(self.send_expect_multi_line(cmd).await?))
        } else {
            self.send_expect_ok(cmd).await?;
            Ok(None)
        }
    }

    // --- Public command methods ---

    // -- Informational --

    /// Query the connection status in the given format.
    ///
    /// Returns the raw multi-line response. Use [`status`](Self::status)
    /// for a typed result.
    pub async fn status_raw(&mut self, format: StatusFormat) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Status(format))
            .await
    }

    /// Query and parse the server-mode connection status.
    pub async fn status(&mut self, format: StatusFormat) -> Result<StatusResponse, ClientError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_status(&lines)?)
    }

    /// Query and parse client-mode statistics.
    pub async fn client_statistics(
        &mut self,
        format: StatusFormat,
    ) -> Result<ClientStatistics, ClientError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_client_statistics(&lines)?)
    }

    /// Query the current state as a multi-line history.
    pub async fn state(&mut self) -> Result<Vec<StateEntry>, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_state_history(&lines)?)
    }

    /// Query the most recent state entry.
    pub async fn current_state(&mut self) -> Result<StateEntry, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_current_state(&lines)?)
    }

    /// Control real-time state notifications.
    ///
    /// Streaming modes (`All`, `OnAll`, `Recent`) return accumulated history
    /// lines. `On`/`Off` return `Ok(None)`.
    pub async fn state_stream(
        &mut self,
        mode: StreamMode,
    ) -> Result<Option<Vec<StateEntry>>, ClientError> {
        match self
            .send_stream_command(mode, OvpnCommand::StateStream(mode))
            .await?
        {
            Some(lines) => Ok(Some(parsed_response::parse_state_history(&lines)?)),
            None => Ok(None),
        }
    }

    /// Query the OpenVPN and management interface version.
    pub async fn version(&mut self) -> Result<VersionInfo, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::Version).await?;
        Ok(parsed_response::parse_version(&lines))
    }

    /// Set the management client version to announce feature support.
    ///
    /// For versions < 4 this produces no response from the server.
    /// For versions >= 4 a `SUCCESS:` response is expected.
    pub async fn set_version(&mut self, version: u32) -> Result<(), ClientError> {
        let cmd = OvpnCommand::SetVersion(version);
        if version < 4 {
            self.framed.send(cmd).await?;
            Ok(())
        } else {
            self.send_expect_ok(cmd).await
        }
    }

    /// Query the PID of the OpenVPN process.
    pub async fn pid(&mut self) -> Result<u32, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::Pid).await?;
        Ok(parsed_response::parse_pid(&payload)?)
    }

    /// List available management commands.
    pub async fn help(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Help).await
    }

    /// Query or set the log verbosity level.
    pub async fn verb(&mut self, level: Option<u8>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Verb(level)).await
    }

    /// Query or set the mute threshold.
    pub async fn mute(&mut self, threshold: Option<u32>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Mute(threshold)).await
    }

    /// (Windows) Show network adapter list.
    pub async fn net(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Net).await
    }

    // -- Notification control --

    /// Control real-time log streaming.
    ///
    /// Streaming modes return accumulated log history. `On`/`Off` return `Ok(None)`.
    pub async fn log(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, ClientError> {
        self.send_stream_command(mode, OvpnCommand::Log(mode)).await
    }

    /// Control real-time echo notifications.
    pub async fn echo(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, ClientError> {
        self.send_stream_command(mode, OvpnCommand::Echo(mode))
            .await
    }

    /// Enable or disable byte count notifications at N-second intervals.
    /// Pass 0 to disable.
    pub async fn bytecount(&mut self, interval: u32) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ByteCount(interval)).await
    }

    // -- Connection control --

    /// Send a signal to the OpenVPN daemon.
    pub async fn signal(&mut self, signal: Signal) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Signal(signal)).await
    }

    /// Kill a specific client connection (server mode).
    pub async fn kill(&mut self, target: KillTarget) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Kill(target)).await
    }

    /// Query the current hold flag.
    pub async fn hold_query(&mut self) -> Result<bool, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::HoldQuery).await?;
        Ok(parsed_response::parse_hold(&payload)?)
    }

    /// Set the hold flag on.
    pub async fn hold_on(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldOn).await
    }

    /// Clear the hold flag.
    pub async fn hold_off(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldOff).await
    }

    /// Release from hold state and start OpenVPN.
    pub async fn hold_release(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldRelease).await
    }

    // -- Authentication --

    /// Supply a username for the given auth type.
    pub async fn username(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Username {
            auth_type,
            value: Redacted::new(value.into()),
        })
        .await
    }

    /// Supply a password for the given auth type.
    pub async fn password(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Password {
            auth_type,
            value: Redacted::new(value.into()),
        })
        .await
    }

    /// Set the auth-retry strategy.
    pub async fn auth_retry(&mut self, mode: AuthRetryMode) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::AuthRetry(mode)).await
    }

    /// Forget all passwords entered during this management session.
    pub async fn forget_passwords(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ForgetPasswords).await
    }

    /// Respond to a CRV1 dynamic challenge.
    pub async fn challenge_response(
        &mut self,
        state_id: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ChallengeResponse {
            state_id: state_id.into(),
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a static challenge.
    pub async fn static_challenge_response(
        &mut self,
        password_b64: impl Into<String>,
        response_b64: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::StaticChallengeResponse {
            password_b64: Redacted::new(password_b64.into()),
            response_b64: Redacted::new(response_b64.into()),
        })
        .await
    }

    /// Respond to a CR_TEXT challenge.
    pub async fn cr_response(&mut self, response: impl Into<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::CrResponse {
            response: Redacted::new(response.into()),
        })
        .await
    }

    // -- Interactive prompts --

    /// Respond to a `>NEED-OK:` prompt.
    pub async fn need_ok(
        &mut self,
        name: impl Into<String>,
        response: NeedOkResponse,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::NeedOk {
            name: name.into(),
            response,
        })
        .await
    }

    /// Respond to a `>NEED-STR:` prompt.
    pub async fn need_str(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::NeedStr {
            name: name.into(),
            value: value.into(),
        })
        .await
    }

    // -- PKCS#11 --

    /// Query available PKCS#11 certificate count.
    pub async fn pkcs11_id_count(&mut self) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdCount).await
    }

    /// Retrieve a PKCS#11 certificate by index.
    pub async fn pkcs11_id_get(&mut self, index: u32) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdGet(index))
            .await
    }

    // -- External key / signatures --

    /// Provide an RSA signature in response to `>RSA_SIGN:`.
    pub async fn rsa_sig(&mut self, base64_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::RsaSig { base64_lines })
            .await
    }

    /// Provide a signature in response to `>PK_SIGN:`.
    pub async fn pk_sig(&mut self, base64_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PkSig { base64_lines })
            .await
    }

    /// Supply an external certificate in response to `>NEED-CERTIFICATE:`.
    pub async fn certificate(&mut self, pem_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Certificate { pem_lines })
            .await
    }

    // -- Client management (server mode) --

    /// Authorize a client and push config directives.
    pub async fn client_auth(
        &mut self,
        cid: u64,
        kid: u64,
        config_lines: Vec<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines,
        })
        .await
    }

    /// Authorize a client without pushing any config.
    pub async fn client_auth_nt(&mut self, cid: u64, kid: u64) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientAuthNt { cid, kid })
            .await
    }

    /// Deny a client connection.
    pub async fn client_deny(&mut self, deny: ClientDeny) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientDeny(deny)).await
    }

    /// Kill a client session by CID.
    pub async fn client_kill(
        &mut self,
        cid: u64,
        message: Option<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientKill { cid, message })
            .await
    }

    /// Defer authentication for a client.
    pub async fn client_pending_auth(
        &mut self,
        cid: u64,
        kid: u64,
        extra: impl Into<String>,
        timeout: u32,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientPendingAuth {
            cid,
            kid,
            extra: extra.into(),
            timeout,
        })
        .await
    }

    // -- Remote / Proxy override --

    /// Respond to a `>REMOTE:` notification.
    pub async fn remote(&mut self, action: RemoteAction) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Remote(action)).await
    }

    /// Respond to a `>PROXY:` notification.
    pub async fn proxy(&mut self, action: ProxyAction) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Proxy(action)).await
    }

    // -- Server statistics --

    /// Request aggregated server stats.
    pub async fn load_stats(&mut self) -> Result<LoadStats, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::LoadStats).await?;
        Ok(parsed_response::parse_load_stats(&payload)?)
    }

    // -- ENV filter --

    /// Set the env-var filter level for `>CLIENT:ENV` blocks.
    pub async fn env_filter(&mut self, level: u32) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::EnvFilter(level)).await
    }

    // -- Remote entry queries --

    /// Query the number of `--remote` entries.
    pub async fn remote_entry_count(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryCount)
            .await
    }

    /// Retrieve `--remote` entries.
    pub async fn remote_entry_get(
        &mut self,
        range: RemoteEntryRange,
    ) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryGet(range))
            .await
    }

    // -- Push updates (server mode) --

    /// Broadcast a push option update to all connected clients.
    pub async fn push_update_broad(
        &mut self,
        options: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PushUpdateBroad {
            options: options.into(),
        })
        .await
    }

    /// Push an option update to a specific client.
    pub async fn push_update_cid(
        &mut self,
        cid: u64,
        options: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PushUpdateCid {
            cid,
            options: options.into(),
        })
        .await
    }

    // -- Management interface auth --

    /// Authenticate to the management interface.
    pub async fn management_password(
        &mut self,
        password: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ManagementPassword(Redacted::new(
            password.into(),
        )))
        .await
    }

    // -- Session lifecycle --

    /// Close the management session. Consumes the client since the
    /// connection is no longer usable.
    pub async fn exit(mut self) -> Result<(), ClientError> {
        self.framed.send(OvpnCommand::Exit).await?;
        Ok(())
    }

    // -- Raw escape hatch --

    /// Send a raw command expecting `SUCCESS:`/`ERROR:`.
    pub async fn raw(&mut self, command: impl Into<String>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Raw(command.into()))
            .await
    }

    /// Send a raw command expecting a multi-line response.
    pub async fn raw_multi_line(
        &mut self,
        command: impl Into<String>,
    ) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RawMultiLine(command.into()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// Create a client connected to a mock transport. Returns the client,
    /// the notification sender, and the server-side of the duplex stream.
    fn mock_client() -> (
        ManagementClient<DuplexStream>,
        broadcast::Sender<Notification>,
        DuplexStream,
    ) {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let framed = Framed::new(client_stream, OvpnCodec::new());
        let (notification_tx, _) = broadcast::channel(64);
        let client = ManagementClient::new(framed, notification_tx.clone());
        (client, notification_tx, server_stream)
    }

    /// Write a sequence of lines to the server side and close it.
    async fn server_respond(server: &mut DuplexStream, lines: &[&str]) {
        for line in lines {
            server.write_all(line.as_bytes()).await.unwrap();
            server.write_all(b"\r\n").await.unwrap();
        }
    }

    #[tokio::test]
    async fn pid_returns_parsed_value() {
        let (mut client, _notif, mut server) = mock_client();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(&mut server, &["SUCCESS: pid=42"]).await;
            server
        });

        let pid = client.pid().await.unwrap();
        assert_eq!(pid, 42);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn notifications_forwarded_during_command() {
        let (mut client, notif_tx, mut server) = mock_client();
        let mut rx = notif_tx.subscribe();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            // Server sends a notification interleaved with the response.
            server_respond(&mut server, &[">BYTECOUNT:1024,2048", "SUCCESS: pid=99"]).await;
            server
        });

        let pid = client.pid().await.unwrap();
        assert_eq!(pid, 99);

        // The notification was forwarded to the broadcast channel.
        let notif = rx.try_recv().unwrap();
        assert!(
            matches!(
                notif,
                Notification::ByteCount {
                    bytes_in: 1024,
                    bytes_out: 2048
                }
            ),
            "expected ByteCount, got {notif:?}"
        );

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn server_error_maps_to_client_error() {
        let (mut client, _notif, mut server) = mock_client();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(&mut server, &["ERROR: command not allowed"]).await;
            server
        });

        let err = client.hold_release().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::ServerError(msg) if msg == "command not allowed"),
            "expected ServerError, got {err:?}"
        );

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn version_returns_parsed_info() {
        let (mut client, _notif, mut server) = mock_client();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(
                &mut server,
                &[
                    "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu",
                    "Management Interface Version: 5",
                    "END",
                ],
            )
            .await;
            server
        });

        let info = client.version().await.unwrap();
        assert_eq!(info.management_version(), Some(5));
        assert!(info.openvpn_version_line().unwrap().contains("2.6.9"));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connection_closed_returns_error() {
        let (mut client, _notif, server) = mock_client();

        // Drop the server side immediately.
        drop(server);

        let err = client.pid().await.unwrap_err();
        // Could be ConnectionClosed or Io depending on timing, both are acceptable.
        assert!(
            matches!(&err, ClientError::ConnectionClosed | ClientError::Io(_)),
            "expected connection error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn multiple_notification_subscribers() {
        let (mut client, notif_tx, mut server) = mock_client();
        let mut rx1 = notif_tx.subscribe();
        let mut rx2 = notif_tx.subscribe();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(
                &mut server,
                &[">HOLD:Waiting for hold release:5", "SUCCESS: pid=1"],
            )
            .await;
            server
        });

        let pid = client.pid().await.unwrap();
        assert_eq!(pid, 1);

        // Both subscribers received the notification.
        let n1 = rx1.try_recv().unwrap();
        let n2 = rx2.try_recv().unwrap();
        assert!(matches!(n1, Notification::Hold { .. }));
        assert!(matches!(n2, Notification::Hold { .. }));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn load_stats_parsed() {
        let (mut client, _notif, mut server) = mock_client();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(
                &mut server,
                &["SUCCESS: nclients=3,bytesin=100000,bytesout=50000"],
            )
            .await;
            server
        });

        let stats = client.load_stats().await.unwrap();
        assert_eq!(stats.nclients, 3);
        assert_eq!(stats.bytesin, 100_000);
        assert_eq!(stats.bytesout, 50_000);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn hold_query_parsed() {
        let (mut client, _notif, mut server) = mock_client();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            let _n = server.read(&mut buf).await.unwrap();
            server_respond(&mut server, &["SUCCESS: hold=1"]).await;
            server
        });

        assert!(client.hold_query().await.unwrap());

        handle.await.unwrap();
    }
}
