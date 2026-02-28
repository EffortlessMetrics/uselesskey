//! Build a JWKS (JSON Web Key Set) from multiple key types.
//!
//! Demonstrates combining RSA and ECDSA public keys into a single JWKS,
//! suitable for serving at `/.well-known/jwks.json` in a test mock.
//!
//! Run with:
//! ```sh
//! cargo run -p uselesskey --example jwks --features "jwk,rsa,ecdsa"
//! ```

#[cfg(all(feature = "jwk", feature = "rsa", feature = "ecdsa"))]
fn main() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Factory, RsaFactoryExt, RsaSpec};

    let fx = Factory::random();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("issuer-ec", EcdsaSpec::es256());

    let mut builder = JwksBuilder::new();
    builder.push_public(rsa.public_jwk());
    builder.push_public(ecdsa.public_jwk());

    let jwks = builder.build();
    println!("{jwks}");
}

#[cfg(not(all(feature = "jwk", feature = "rsa", feature = "ecdsa")))]
fn main() {
    eprintln!("Enable 'jwk', 'rsa', and 'ecdsa' features to run this example.");
}
