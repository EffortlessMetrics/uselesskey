use uselesskey_core::Factory;

use crate::{MaterializeError, MaterializeFixtureSpec, MaterializeKind, fallback_label};

mod entropy;
mod pem_shape;
mod rsa;
mod ssh_shape;
mod token;

pub(crate) fn materialized_fixture_bytes(
    spec: &MaterializeFixtureSpec,
) -> Result<Vec<u8>, MaterializeError> {
    let label = spec
        .label
        .clone()
        .unwrap_or_else(|| fallback_label(&spec.out));
    let fx = Factory::deterministic_from_str(&spec.seed);

    match spec.kind {
        MaterializeKind::EntropyBytes => Ok(entropy::entropy_bytes(&spec.seed, spec.len)),
        MaterializeKind::TokenJwtShape => Ok(token::jwt_shape(&fx, &label)),
        MaterializeKind::RsaPkcs8Der => rsa::pkcs8_der(&fx, &label),
        MaterializeKind::RsaPkcs8Pem => rsa::pkcs8_pem(&fx, &label),
        MaterializeKind::PemBlockShape => pem_shape::pem_block_shape(&spec.seed, &label, spec.len),
        MaterializeKind::SshPublicKeyShape => {
            Ok(ssh_shape::ssh_public_key_shape(&spec.seed, &label))
        }
        MaterializeKind::TokenApiKey => Ok(token::api_key(&fx, &label)),
    }
}
