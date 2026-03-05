//! X.509 negative-fixture helpers.
//!
//! Policy enums and helper functions are provided by `uselesskey-x509-negative`
//! and re-exported here for backwards compatibility.

pub use uselesskey_x509_negative::{
    X509Negative, corrupt_cert_der_deterministic, corrupt_cert_pem, corrupt_cert_pem_deterministic,
    truncate_cert_der,
};
