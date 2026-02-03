//! Negative fixture helpers.
//!
//! These helpers intentionally produce “bad but shaped” inputs so you can test error paths
//! without committing blobs into git.

mod der;
mod pem;

pub use der::{flip_byte, truncate_der};
pub use pem::{corrupt_pem, CorruptPem};
