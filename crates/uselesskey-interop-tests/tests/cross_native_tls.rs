#[cfg(feature = "cross-native")]
mod cross_native {
    use uselesskey_core::Factory;
    use uselesskey_openssl::OpensslChainExt;
    use uselesskey_webpki::verify_server_cert;
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    #[test]
    fn chain_is_consumable_by_openssl_and_webpki() {
        let fx = Factory::random();
        let chain = fx.x509_chain("cross-native", ChainSpec::new("native-interop.example.test"));

        let openssl_leaf = chain.leaf_cert_openssl();
        assert_ne!(openssl_leaf.subject_name().entries().count(), 0);

        verify_server_cert(&chain, "native-interop.example.test")
            .expect("webpki verification should succeed");
    }
}
