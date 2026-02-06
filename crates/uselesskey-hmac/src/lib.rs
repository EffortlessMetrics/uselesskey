#![forbid(unsafe_code)]

mod secret;
mod spec;

pub use secret::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret};
pub use spec::HmacSpec;
