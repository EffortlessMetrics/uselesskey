#![forbid(unsafe_code)]

mod secret;
mod spec;

pub use secret::{HmacFactoryExt, HmacSecret, DOMAIN_HMAC_SECRET};
pub use spec::HmacSpec;
