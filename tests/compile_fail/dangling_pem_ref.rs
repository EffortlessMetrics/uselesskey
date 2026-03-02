/// Verify that holding a reference to PEM data beyond the keypair's
/// lifetime produces a clear borrow-checker error.
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

fn main() {
    let pem: &str;
    {
        let fx = Factory::random();
        let kp = fx.ecdsa("test", EcdsaSpec::es256());
        pem = kp.private_key_pkcs8_pem();
    }
    println!("{}", pem);
}
