/// Action for the `remote` command (sent in response to a `>REMOTE:`
/// notification, requires `--management-query-remote`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAction {
    /// Accept the connection entry as-is.
    Accept,
    /// Skip this entry and advance to the next `--remote`.
    Skip,
    /// Override the host and port.
    Modify { host: String, port: u16 },
}
