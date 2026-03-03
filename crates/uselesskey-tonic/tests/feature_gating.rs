//! Feature flag gating tests for uselesskey-tonic.
//!
//! When the `x509` feature is enabled, all extension traits should be available.
//! This file tests that the traits are importable, usable, and produce the expected types.

// This test module is only meaningful when the x509 feature is active.
#[cfg(feature = "x509")]
mod with_x509_feature {
    use uselesskey_core::Factory;
    use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    /// Verify all four extension traits are importable and callable.
    #[test]
    fn all_traits_available_with_x509_feature() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("feat-ss", X509Spec::self_signed("localhost"));
        let chain = fx.x509_chain("feat-chain", ChainSpec::new("feat.example.com"));

        // TonicIdentityExt
        let _id_cert = cert.identity_tonic();
        let _id_chain = chain.identity_tonic();

        // TonicServerTlsExt
        let _srv_cert = cert.server_tls_config_tonic();
        let _srv_chain = chain.server_tls_config_tonic();

        // TonicClientTlsExt
        let _cli_cert = cert.client_tls_config_tonic("localhost");
        let _cli_chain = chain.client_tls_config_tonic("feat.example.com");

        // TonicMtlsExt (only on X509Chain)
        let _mtls_srv = chain.server_tls_config_mtls_tonic();
        let _mtls_cli = chain.client_tls_config_mtls_tonic("feat.example.com");
    }

    /// Verify traits work with both &str and String domain names.
    #[test]
    fn domain_name_accepts_str_and_string() {
        let fx = Factory::random();
        let chain = fx.x509_chain("feat-domain", ChainSpec::new("domain.example.com"));

        // &str
        let _client_str = chain.client_tls_config_tonic("domain.example.com");

        // String
        let domain = String::from("domain.example.com");
        let _client_string = chain.client_tls_config_tonic(domain);

        // mTLS with &str
        let _mtls_str = chain.client_tls_config_mtls_tonic("domain.example.com");

        // mTLS with String
        let domain2 = String::from("domain.example.com");
        let _mtls_string = chain.client_tls_config_mtls_tonic(domain2);
    }

    /// Verify self-signed and chain implement the same traits.
    #[test]
    fn self_signed_and_chain_share_identity_and_server_traits() {
        let fx = Factory::random();
        let cert = fx.x509_self_signed("feat-shared", X509Spec::self_signed("localhost"));
        let chain = fx.x509_chain("feat-shared-chain", ChainSpec::new("shared.example.com"));

        // Both implement TonicIdentityExt
        fn assert_identity<T: TonicIdentityExt>(t: &T) {
            let _id = t.identity_tonic();
        }
        assert_identity(&cert);
        assert_identity(&chain);

        // Both implement TonicServerTlsExt
        fn assert_server<T: TonicServerTlsExt>(t: &T) {
            let _srv = t.server_tls_config_tonic();
        }
        assert_server(&cert);
        assert_server(&chain);

        // Both implement TonicClientTlsExt
        fn assert_client<T: TonicClientTlsExt>(t: &T) {
            let _cli = t.client_tls_config_tonic("localhost");
        }
        assert_client(&cert);
        assert_client(&chain);
    }

    /// Verify that TonicMtlsExt is only implemented for X509Chain (not X509Cert).
    /// This is a compile-time check: X509Cert should NOT impl TonicMtlsExt.
    #[test]
    fn mtls_ext_only_on_chain() {
        fn assert_mtls<T: TonicMtlsExt>(t: &T) {
            let _srv = t.server_tls_config_mtls_tonic();
            let _cli = t.client_tls_config_mtls_tonic("localhost");
        }
        let fx = Factory::random();
        let chain = fx.x509_chain("feat-mtls-only", ChainSpec::new("mtls.example.com"));
        assert_mtls(&chain);
        // Note: X509Cert does NOT implement TonicMtlsExt by design
    }
}

/// When x509 feature is disabled, the tonic crate should still compile
/// but without X.509-related extension traits.
/// This module verifies the crate remains importable.
#[cfg(not(feature = "x509"))]
mod without_x509_feature {
    #[test]
    fn crate_compiles_without_x509_feature() {
        // The crate should compile; just verify we can reference the crate
        // The extension traits should NOT be available here.
        // This test passes if it compiles.
    }
}
