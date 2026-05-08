#![forbid(unsafe_code)]

//! Deprecated compatibility shim for deterministic X.509 derivation helpers.
//!
//! Prefer `uselesskey-x509`; the canonical implementation now lives there.

pub use uselesskey_x509::srp::derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};
