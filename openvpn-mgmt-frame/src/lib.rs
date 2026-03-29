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
