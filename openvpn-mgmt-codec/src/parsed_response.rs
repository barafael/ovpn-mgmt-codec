//! Typed parsers for `SUCCESS:` payloads and multi-line responses.
//!
//! The management protocol's `SUCCESS:` line carries structured data as a
//! plain string (e.g. `SUCCESS: pid=12345`). These utilities parse common
//! payloads into typed values, saving every consumer from re-implementing
//! the same string splitting.
//!
//! # Examples
//!
//! ```
//! use openvpn_mgmt_codec::parsed_response::{parse_pid, parse_load_stats, LoadStats};
//!
//! assert_eq!(parse_pid("pid=12345"), Ok(12345));
//!
//! let stats = parse_load_stats("nclients=3,bytesin=100000,bytesout=50000").unwrap();
//! assert_eq!(stats.nclients, 3);
//! ```

use crate::version_info::VersionInfo;

/// Aggregated server statistics from `load-stats`.
///
/// Wire format: `SUCCESS: nclients=N,bytesin=N,bytesout=N`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    /// Number of currently connected clients.
    pub nclients: u64,
    /// Total bytes received by the server.
    pub bytesin: u64,
    /// Total bytes sent by the server.
    pub bytesout: u64,
}

/// Error returned when a `SUCCESS:` payload cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseResponseError {
    /// Expected `pid=N` but the prefix was missing.
    #[error("missing 'pid=' prefix in: {0:?}")]
    MissingPidPrefix(String),

    /// Expected `hold=0` or `hold=1` but the prefix was missing.
    #[error("missing 'hold=' prefix in: {0:?}")]
    MissingHoldPrefix(String),

    /// `hold=` value was not `0` or `1`.
    #[error("invalid hold value: {0:?}")]
    InvalidHoldValue(String),

    /// A numeric field could not be parsed.
    #[error("invalid integer for field {field:?}: {value:?}")]
    InvalidInteger {
        /// The field name that failed to parse.
        field: &'static str,
        /// The raw value that could not be parsed.
        value: String,
    },

    /// A required field was missing from the `load-stats` payload.
    #[error("missing field {0:?} in load-stats payload")]
    MissingField(&'static str),

    /// An unrecognized key appeared in the `load-stats` payload.
    #[error("unexpected field {0:?} in load-stats payload")]
    UnexpectedField(String),
}

/// Parse the `SUCCESS:` payload from a `pid` command.
///
/// Expects the format `pid=N` and returns the PID as `u32`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_pid;
/// assert_eq!(parse_pid("pid=12345"), Ok(12345));
/// assert!(parse_pid("garbage").is_err());
/// ```
pub fn parse_pid(payload: &str) -> Result<u32, ParseResponseError> {
    let val = payload
        .strip_prefix("pid=")
        .ok_or_else(|| ParseResponseError::MissingPidPrefix(payload.to_string()))?;
    val.parse().map_err(|_| ParseResponseError::InvalidInteger {
        field: "pid",
        value: val.to_string(),
    })
}

/// Parse the `SUCCESS:` payload from a `load-stats` command.
///
/// Expects the format `nclients=N,bytesin=N,bytesout=N`.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_load_stats;
/// let stats = parse_load_stats("nclients=5,bytesin=1000,bytesout=2000").unwrap();
/// assert_eq!(stats.nclients, 5);
/// assert_eq!(stats.bytesin, 1000);
/// assert_eq!(stats.bytesout, 2000);
/// ```
pub fn parse_load_stats(payload: &str) -> Result<LoadStats, ParseResponseError> {
    let mut nclients = None;
    let mut bytesin = None;
    let mut bytesout = None;

    for part in payload.split(',') {
        if let Some((key, val)) = part.split_once('=') {
            let parsed = |field| {
                val.parse().map_err(|_| ParseResponseError::InvalidInteger {
                    field,
                    value: val.to_string(),
                })
            };
            match key {
                "nclients" => nclients = Some(parsed("nclients")?),
                "bytesin" => bytesin = Some(parsed("bytesin")?),
                "bytesout" => bytesout = Some(parsed("bytesout")?),
                other => return Err(ParseResponseError::UnexpectedField(other.to_string())),
            }
        }
    }

    Ok(LoadStats {
        nclients: nclients.ok_or(ParseResponseError::MissingField("nclients"))?,
        bytesin: bytesin.ok_or(ParseResponseError::MissingField("bytesin"))?,
        bytesout: bytesout.ok_or(ParseResponseError::MissingField("bytesout"))?,
    })
}

/// Parse the `SUCCESS:` payload from a `hold` query.
///
/// Expects the format `hold=0` or `hold=1`. Returns `true` when hold is
/// active.
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_hold;
/// assert_eq!(parse_hold("hold=1"), Ok(true));
/// assert_eq!(parse_hold("hold=0"), Ok(false));
/// ```
pub fn parse_hold(payload: &str) -> Result<bool, ParseResponseError> {
    let val = payload
        .strip_prefix("hold=")
        .ok_or_else(|| ParseResponseError::MissingHoldPrefix(payload.to_string()))?;
    match val {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(ParseResponseError::InvalidHoldValue(val.to_string())),
    }
}

/// Parse the multi-line response from a `version` command into a
/// [`VersionInfo`].
///
/// This is a convenience wrapper around [`VersionInfo::parse`].
///
/// ```
/// use openvpn_mgmt_codec::parsed_response::parse_version;
///
/// let lines = vec![
///     "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu".to_string(),
///     "Management Interface Version: 5".to_string(),
/// ];
/// let info = parse_version(&lines);
/// assert_eq!(info.management_version(), Some(5));
/// ```
pub fn parse_version(lines: &[String]) -> VersionInfo {
    VersionInfo::parse(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_pid ---

    #[test]
    fn pid_normal() {
        assert_eq!(parse_pid("pid=42"), Ok(42));
    }

    #[test]
    fn pid_zero() {
        assert_eq!(parse_pid("pid=0"), Ok(0));
    }

    #[test]
    fn pid_missing_prefix() {
        assert!(parse_pid("42").is_err());
    }

    #[test]
    fn pid_not_a_number() {
        assert!(parse_pid("pid=abc").is_err());
    }

    // --- parse_load_stats ---

    #[test]
    fn load_stats_normal() {
        let s = parse_load_stats("nclients=10,bytesin=123456,bytesout=789012").unwrap();
        assert_eq!(s.nclients, 10);
        assert_eq!(s.bytesin, 123456);
        assert_eq!(s.bytesout, 789012);
    }

    #[test]
    fn load_stats_reordered() {
        let s = parse_load_stats("bytesout=1,nclients=2,bytesin=3").unwrap();
        assert_eq!(s.nclients, 2);
        assert_eq!(s.bytesin, 3);
        assert_eq!(s.bytesout, 1);
    }

    #[test]
    fn load_stats_missing_field() {
        let err = parse_load_stats("nclients=1,bytesin=2").unwrap_err();
        assert!(matches!(err, ParseResponseError::MissingField("bytesout")));
    }

    #[test]
    fn load_stats_non_numeric_value() {
        let err = parse_load_stats("nclients=abc,bytesin=2,bytesout=3").unwrap_err();
        assert!(matches!(
            err,
            ParseResponseError::InvalidInteger {
                field: "nclients",
                ..
            }
        ));
    }

    #[test]
    fn load_stats_unexpected_field() {
        let err = parse_load_stats("nclients=1,bytesin=2,bytesout=3,extra=99").unwrap_err();
        assert!(matches!(err, ParseResponseError::UnexpectedField(f) if f == "extra"));
    }

    // --- parse_hold ---

    #[test]
    fn hold_active() {
        assert_eq!(parse_hold("hold=1"), Ok(true));
    }

    #[test]
    fn hold_inactive() {
        assert_eq!(parse_hold("hold=0"), Ok(false));
    }

    #[test]
    fn hold_missing_prefix() {
        assert!(parse_hold("garbage").is_err());
    }

    #[test]
    fn hold_invalid_value() {
        assert!(parse_hold("hold=maybe").is_err());
    }

    // --- parse_version ---

    #[test]
    fn version_roundtrip() {
        let lines = vec![
            "OpenVPN Version: OpenVPN 2.5.0".to_string(),
            "Management Interface Version: 4".to_string(),
        ];
        let info = parse_version(&lines);
        assert_eq!(info.management_version(), Some(4));
    }
}
