/// Verify that passing the wrong spec type (EcdsaSpec to rsa()) produces
/// a clear compile-time type error.
use uselesskey_core::Factory;
use uselesskey_ecdsa::EcdsaSpec;
use uselesskey_rsa::RsaFactoryExt;

fn main() {
    let fx = Factory::random();
    let _kp = fx.rsa("test", EcdsaSpec::es256());
}
