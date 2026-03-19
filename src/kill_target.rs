/// How to identify a client to kill (server mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillTarget {
    /// Kill by Common Name from the client's TLS certificate.
    CommonName(String),
    /// Kill by exact `IP:port` of the client's real address.
    Address { ip: String, port: u16 },
}
