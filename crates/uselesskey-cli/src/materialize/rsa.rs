use uselesskey_core::Factory;
#[cfg(feature = "rsa-materialize")]
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use crate::MaterializeError;

pub(super) fn pkcs8_der(fx: &Factory, label: &str) -> Result<Vec<u8>, MaterializeError> {
    #[cfg(feature = "rsa-materialize")]
    {
        Ok(fx
            .rsa(label, RsaSpec::rs256())
            .private_key_pkcs8_der()
            .to_vec())
    }
    #[cfg(not(feature = "rsa-materialize"))]
    {
        let _ = (fx, label);
        Err(MaterializeError::InvalidManifest(
            "rsa.pkcs8_der requires uselesskey-cli feature `rsa-materialize`".to_string(),
        ))
    }
}

pub(super) fn pkcs8_pem(fx: &Factory, label: &str) -> Result<Vec<u8>, MaterializeError> {
    #[cfg(feature = "rsa-materialize")]
    {
        Ok(fx
            .rsa(label, RsaSpec::rs256())
            .private_key_pkcs8_pem()
            .as_bytes()
            .to_vec())
    }
    #[cfg(not(feature = "rsa-materialize"))]
    {
        let _ = (fx, label);
        Err(MaterializeError::InvalidManifest(
            "rsa.pkcs8_pem requires uselesskey-cli feature `rsa-materialize`".to_string(),
        ))
    }
}
