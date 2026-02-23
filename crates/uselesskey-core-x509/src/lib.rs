#![forbid(unsafe_code)]

//! Deterministic X.509 fixture policy helpers.
//!
//! This crate centralizes reusable policy used by X.509 fixture producers:
//! - X.509 spec/negative policy types used by fixture generators
//! - re-exports of deterministic derivation helpers from
//!   `uselesskey-core-x509-derive`

mod chain_spec;
mod negative;
mod spec;

pub use chain_spec::ChainSpec;
pub use negative::{ChainNegative, X509Negative};
pub use spec::{KeyUsage, NotBeforeOffset, X509Spec};
pub use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};
