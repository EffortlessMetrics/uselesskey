/// Verify that calling an extension method without importing the trait
/// produces a clear "method not found" error, guiding the user to import
/// the correct trait.
use uselesskey_core::Factory;
use uselesskey_rsa::RsaSpec;

fn main() {
    let fx = Factory::random();
    // RsaFactoryExt is not imported — should fail with a helpful error.
    let _kp = fx.rsa("test", RsaSpec::rs256());
}
