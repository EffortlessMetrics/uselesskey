//! Negative fixture helpers.
//!
//! These helpers intentionally produce "bad but shaped" inputs so you can test error paths
//! without committing blobs into git.
//!
//! # Overview
//!
//! Negative fixtures are test inputs designed to trigger error handling code paths.
//! This module provides:
//!
//! - **PEM corruption**: [`corrupt_pem`] with various [`CorruptPem`] strategies
//! - **DER manipulation**: [`truncate_der`] and [`flip_byte`]
//! - **Deterministic variant corruption**: [`corrupt_pem_deterministic`]
//!   and [`corrupt_der_deterministic`]
//!
//! # Examples
//!
//! ## Corrupting PEM
//!
//! ```
//! use uselesskey_core::negative::{corrupt_pem, CorruptPem};
//!
//! let valid_pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
//!
//! // Corrupt the header
//! let bad = corrupt_pem(valid_pem, CorruptPem::BadHeader);
//! assert!(bad.contains("CORRUPTED"));
//!
//! // Truncate to 20 bytes
//! let truncated = corrupt_pem(valid_pem, CorruptPem::Truncate { bytes: 20 });
//! assert_eq!(truncated.len(), 20);
//! ```
//!
//! ## Manipulating DER
//!
//! ```
//! use uselesskey_core::negative::{truncate_der, flip_byte};
//!
//! let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D];
//!
//! // Truncate to cause parse failure
//! let truncated = truncate_der(&der, 3);
//! assert_eq!(truncated.len(), 3);
//!
//! // Flip a byte to corrupt the structure
//! let flipped = flip_byte(&der, 0);
//! assert_eq!(flipped[0], 0x31); // 0x30 XOR 0x01
//! ```

mod der;
mod pem;

pub use der::{corrupt_der_deterministic, flip_byte, truncate_der};
pub use pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
