/// Response to a `>NEED-OK:` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum NeedOkResponse {
    /// Accept the prompt.
    Ok,

    /// Reject the prompt.
    Cancel,
}
