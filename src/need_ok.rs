use std::fmt;

/// Response to a `>NEED-OK:` prompt.
#[derive(Debug, Clone, Copy)]
pub enum NeedOkResponse {
    Ok,
    Cancel,
}

impl fmt::Display for NeedOkResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Cancel => f.write_str("cancel"),
        }
    }
}
