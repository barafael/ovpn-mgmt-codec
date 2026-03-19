use std::fmt;

/// Authentication credential type. OpenVPN identifies credential requests
/// by a quoted type string — usually `"Auth"` or `"Private Key"`, but
/// plugins can define custom types. This is a newtype so you're not locked
/// into a closed enum.
#[derive(Debug, Clone)]
pub struct AuthType(pub String);

impl AuthType {
    /// Standard `--auth-user-pass` authentication.
    pub fn auth() -> Self {
        Self("Auth".to_owned())
    }
    /// Private key passphrase (encrypted key file).
    pub fn private_key() -> Self {
        Self("Private Key".to_owned())
    }
}

/// Controls how OpenVPN retries after authentication failure.
#[derive(Debug, Clone, Copy)]
pub enum AuthRetryMode {
    /// Don't retry — exit on auth failure.
    None,
    /// Retry, re-prompting for credentials.
    Interact,
    /// Retry without re-prompting.
    NoInteract,
}

impl fmt::Display for AuthRetryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Interact => f.write_str("interact"),
            Self::NoInteract => f.write_str("nointeract"),
        }
    }
}
