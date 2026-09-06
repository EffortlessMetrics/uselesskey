# No-panic inventory after tempfile sink slice

Source: `dcf61671516b775f2aa15885c500caf3cbdd6c81`

- Represented findings: **3,351**
- Unique identities: **3,351**
- Rust files: **232**

| Rank | Path | Findings | Families |
|---:|---|---:|---|
| 1 | `crates/uselesskey-bdd-steps/src/lib.rs` | 759 | expect=725, panic_macro=4, unwrap=30 |
| 2 | `xtask/src/main.rs` | 158 | expect=86, panic_macro=1, unwrap=71 |
| 3 | `crates/uselesskey-x509/tests/x509_comprehensive.rs` | 113 | expect=72, panic_macro=10, unwrap=31 |
| 4 | `crates/uselesskey-jsonwebtoken/tests/jwt_comprehensive.rs` | 53 | panic_macro=25, unwrap=28 |
| 5 | `crates/uselesskey-rustls/src/config.rs` | 51 | expect=24, unwrap=27 |
| 6 | `crates/uselesskey-interop-tests/tests/cross_adapter.rs` | 49 | expect=29, unwrap=20 |
| 7 | `crates/uselesskey-interop-tests/tests/cross_adapter_interop_matrix.rs` | 48 | expect=27, unwrap=21 |
| 8 | `crates/uselesskey-interop-tests/tests/cross_adapter_roundtrip.rs` | 43 | expect=26, unwrap=17 |
| 9 | `crates/uselesskey-interop-tests/tests/x509_tls_extended.rs` | 42 | expect=1, unwrap=41 |
| 10 | `tests/jwt_integration.rs` | 41 | expect=33, panic_macro=8 |
| 11 | `crates/uselesskey-aws-lc-rs/tests/integration_aws.rs` | 38 | expect=30, unwrap=8 |
| 12 | `tests/pem_der_format.rs` | 38 | expect=23, panic_macro=9, unwrap=6 |
| 13 | `crates/uselesskey-interop-tests/tests/random_mode.rs` | 37 | expect=25, unwrap=12 |
| 14 | `crates/uselesskey-aws-lc-rs/tests/aws_lc_rs_comprehensive.rs` | 36 | expect=22, panic_macro=2, unwrap=12 |
| 15 | `crates/uselesskey-test-server/src/lib.rs` | 36 | expect=36 |
| 16 | `crates/uselesskey-jsonwebtoken/tests/jwt_extended.rs` | 35 | panic_macro=2, unwrap=33 |
| 17 | `crates/uselesskey/tests/integration_facade.rs` | 34 | unwrap=34 |
| 18 | `crates/uselesskey-ring/tests/ring_comprehensive.rs` | 33 | expect=19, panic_macro=2, unwrap=12 |
| 19 | `crates/uselesskey-interop-tests/tests/all_adapters.rs` | 32 | expect=32 |
| 20 | `crates/uselesskey-token/tests/comprehensive_token.rs` | 32 | unwrap=32 |
| 21 | `crates/uselesskey-jsonwebtoken/tests/snapshots_jwt.rs` | 31 | unwrap=31 |
| 22 | `crates/uselesskey-ring/tests/ring_multi_scheme.rs` | 30 | expect=22, unwrap=8 |
| 23 | `tests/concurrency.rs` | 28 | expect=1, panic_macro=1, unwrap=26 |
| 24 | `crates/uselesskey-rustls/tests/tls_data_transfer.rs` | 27 | expect=3, panic_macro=2, unwrap=22 |
| 25 | `crates/uselesskey-token/tests/token_comprehensive.rs` | 26 | expect=1, unwrap=25 |
| 26 | `crates/uselesskey/tests/e2e_pipeline.rs` | 26 | expect=8, unwrap=18 |
| 27 | `crates/uselesskey-axum/tests/integration.rs` | 25 | expect=5, unwrap=20 |
| 28 | `crates/uselesskey-cli/tests/tls_profile.rs` | 25 | expect=25 |
| 29 | `crates/uselesskey-jsonwebtoken/src/lib.rs` | 25 | expect=7, unwrap=18 |
| 30 | `crates/uselesskey-x509/tests/negative_x509.rs` | 25 | expect=20, panic_macro=1, unwrap=4 |
| 31 | `crates/uselesskey-ecdsa/tests/jwk_private.rs` | 23 | expect=11, unwrap=12 |
| 32 | `crates/uselesskey-interop-tests/tests/cross_adapter_signing.rs` | 23 | expect=23 |
| 33 | `crates/uselesskey-interop-tests/tests/cross_verify.rs` | 23 | expect=23 |
| 34 | `crates/uselesskey-x509/src/chain_negative.rs` | 23 | expect=17, unwrap=6 |
| 35 | `tests/e2e_workflows.rs` | 23 | expect=22, unwrap=1 |
| 36 | `crates/uselesskey-aws-lc-rs/tests/aws_lc_rs_multi_scheme.rs` | 22 | expect=11, panic_macro=3, unwrap=8 |
| 37 | `crates/uselesskey-rustcrypto/tests/adapter_integration.rs` | 22 | expect=19, unwrap=3 |
| 38 | `crates/uselesskey-x509/src/cert.rs` | 22 | expect=12, panic_macro=3, unwrap=7 |
| 39 | `crates/uselesskey/tests/facade_integration.rs` | 22 | expect=3, unwrap=19 |
| 40 | `crates/uselesskey-pgp/src/keypair.rs` | 21 | expect=14, unwrap=7 |
| 41 | `crates/uselesskey-ring/tests/adapter_integration.rs` | 21 | expect=10, unwrap=11 |
| 42 | `crates/uselesskey/tests/feature_combinations.rs` | 21 | expect=1, unwrap=20 |
| 43 | `crates/uselesskey-rustls/tests/adapter_integration.rs` | 20 | expect=2, panic_macro=4, unwrap=14 |
| 44 | `crates/uselesskey-rustls/tests/rustls_comprehensive.rs` | 20 | expect=4, unwrap=16 |
| 45 | `crates/uselesskey-ecdsa/tests/keypair.rs` | 19 | expect=16, unwrap=3 |
| 46 | `crates/uselesskey-ed25519/tests/jwk_private.rs` | 19 | expect=7, unwrap=12 |
| 47 | `crates/uselesskey-interop-tests/tests/cross_adapter_tls.rs` | 19 | expect=7, unwrap=12 |
| 48 | `crates/uselesskey-x509/src/chain.rs` | 19 | expect=11, unwrap=8 |
| 49 | `xtask/src/receipt.rs` | 19 | expect=15, unwrap=4 |
| 50 | `tests/governance.rs` | 18 | expect=12, panic_macro=5, unwrap=1 |
