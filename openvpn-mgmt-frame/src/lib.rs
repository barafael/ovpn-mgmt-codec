//! Low-level line framing for the OpenVPN management protocol.
//!
//! This crate provides:
//!
//! - [`Frame`] — a classified line from the management interface
//! - [`FrameDecoder`] — a stateless-ish [`tokio_util::codec::Decoder`] that
//!   splits the byte stream into [`Frame`] values
//! - Encoder primitives ([`write_line`], [`write_block`], [`wire_safe`],
//!   [`escape`], [`quote`]) for building wire-format commands
//!
//! The decoder does **not** track which command was sent — it classifies
//! each line purely from its content. Multi-line response accumulation
//! (grouping `Line`/`End` sequences) is left to higher layers.
//!
//! `>CLIENT:ENV` accumulation **is** handled here because the protocol
//! guarantees atomicity for that block and the individual ENV lines are
//! not meaningful on their own.
//!
//! # Decoding frames
//!
//! ```
//! use bytes::BytesMut;
//! use tokio_util::codec::Decoder;
//! use openvpn_mgmt_frame::{Frame, FrameDecoder};
//!
//! let mut decoder = FrameDecoder::new();
//! let mut buf = BytesMut::from("SUCCESS: pid=1234\n>HOLD:Waiting for hold release:0\n");
//!
//! assert_eq!(
//!     decoder.decode(&mut buf).unwrap(),
//!     Some(Frame::Success("pid=1234".to_string())),
//! );
//! assert_eq!(
//!     decoder.decode(&mut buf).unwrap(),
//!     Some(Frame::Notification {
//!         kind: "HOLD".to_string(),
//!         payload: "Waiting for hold release:0".to_string(),
//!     }),
//! );
//! assert_eq!(decoder.decode(&mut buf).unwrap(), None); // buffer drained
//! ```
//!
//! # Encoding commands
//!
//! ```
//! use bytes::BytesMut;
//! use openvpn_mgmt_frame::{write_line, write_block, escape, quote, EncoderMode};
//!
//! let mut buf = BytesMut::new();
//! write_line(&mut buf, "status 3");
//! assert_eq!(&buf[..], b"status 3\n");
//!
//! buf.clear();
//! write_block(&mut buf, "client-auth 1 2", &["push-reply".to_string()], EncoderMode::Sanitize).unwrap();
//! assert_eq!(&buf[..], b"client-auth 1 2\npush-reply\nEND\n");
//! ```
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod decoder;
mod encoder;
mod frame;

pub use decoder::FrameDecoder;
pub use encoder::{
    AccumulationLimit, EncodeError, EncoderMode, escape, quote, wire_safe, write_block, write_line,
};
pub use frame::Frame;
