//! Compatibility façade for the canonical feature grid definitions.
//!
//! The implementation moved to `uselesskey-feature-grid` so there is a single
//! source of truth. This crate preserves the historical crate name used by
//! automation and external consumers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use uselesskey_feature_grid::*;
