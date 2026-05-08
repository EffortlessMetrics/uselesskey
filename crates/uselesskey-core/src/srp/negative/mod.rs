//! Generic negative fixture helpers.

pub mod der;
pub mod pem;

pub use der::{corrupt_der_deterministic, flip_byte, truncate_der};
pub use pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
