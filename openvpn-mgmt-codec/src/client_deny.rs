/// Denial of a `>CLIENT:CONNECT` or `>CLIENT:REAUTH` request.
///
/// Wire format: `client-deny {CID} {KID} "reason" ["client-reason"]`
///
/// Use the generated builder for ergonomic construction:
///
/// ```
/// # use openvpn_mgmt_codec::ClientDeny;
/// let deny = ClientDeny::builder()
///     .cid(42)
///     .kid(0)
///     .reason("expired certificate")
///     .client_reason("Your certificate has expired.")
///     .build();
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct ClientDeny {
    /// Client ID from the `>CLIENT:` notification.
    pub cid: u64,

    /// Key ID from the `>CLIENT:` notification.
    pub kid: u64,

    /// Server-side reason string (logged but not sent to client).
    #[builder(into)]
    pub reason: String,

    /// Optional message sent to the client as part of AUTH_FAILED.
    #[builder(into)]
    pub client_reason: Option<String>,
}
