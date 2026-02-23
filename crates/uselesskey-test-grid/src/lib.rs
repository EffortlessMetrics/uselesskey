#![forbid(unsafe_code)]

//! Compatibility façade for the canonical feature grid definitions.
//!
//! The implementation moved to `uselesskey-feature-grid` so there is a single
//! source of truth. This crate preserves the historical crate name used by
//! automation and external consumers.

pub use uselesskey_feature_grid::*;
