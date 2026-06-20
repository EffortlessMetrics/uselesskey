# Negative Fixture Matrix

This page is the human mirror of
[`policy/negative-fixtures.toml`](../../policy/negative-fixtures.toml). It
answers whether a taxonomy class is available product behavior, accepted but
planned, deferred, or out of scope.

The taxonomy contract lives in
[`USELESSKEY-SPEC-0016`](../specs/USELESSKEY-SPEC-0016-negative-fixture-taxonomy.md).
Machine-readable product surfaces should branch on stable IDs, not display
labels.

## Status Values

| Status | Meaning |
| --- | --- |
| `implemented` | The class has an owner crate or bundle surface, tests, docs/status mapping, and stable ID. |
| `accepted_planned` | The class is accepted by taxonomy, but not exposed as current product behavior. |
| `deferred` | The class is useful, but parked outside the current product lane. |
| `out_of_scope` | The class would overclaim provider compatibility, production security, or scanner-evasion behavior. |

## JWK / JWKS

| Stable ID | Status | Public surface | Bundle exposed | Proof |
| --- | --- | --- | --- | --- |
| `jwk_missing_kid` | `implemented` | `NegativeJwk::MissingKid` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwk_wrong_kty` | `implemented` | `NegativeJwk::WrongKty` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwk_unsupported_alg` | `implemented` | `NegativeJwk::UnsupportedAlg` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwk_malformed_base64url` | `implemented` | `NegativeJwk::MalformedBase64url` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwk_mismatched_parameters` | `implemented` | `NegativeJwk::MismatchedParameters` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwks_empty_keys` | `implemented` | `NegativeJwks::EmptyKeys` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwks_missing_kid` | `implemented` | `NegativeJwks::MissingKid` | `oidc` | `cargo test -p uselesskey-cli --all-features bundle` |
| `jwks_duplicate_kid` | `implemented` | `NegativeJwks::DuplicateKid` | `oidc` | `cargo test -p uselesskey-cli --all-features bundle` |
| `jwks_duplicate_key` | `implemented` | `NegativeJwks::DuplicateKey` | no | `cargo test -p uselesskey-jwk --all-features` |
| `jwks_mixed_valid_invalid` | `implemented` | `NegativeJwks::MixedValidInvalid` | no | `cargo test -p uselesskey-jwk --all-features` |

## JWT / Token

| Stable ID | Status | Public surface | Bundle exposed | Proof |
| --- | --- | --- | --- | --- |
| `jwt_bad_segment_count` | `implemented` | `NegativeToken::MalformedJwtSegmentCount` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_malformed_base64url` | `implemented` | `NegativeToken::BadBase64UrlSegment` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_invalid_header_shape` | `implemented` | `NegativeToken::InvalidJwtHeaderShape` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_missing_alg` | `implemented` | `NegativeToken::MissingAlg` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_alg_none` | `implemented` | `NegativeToken::AlgNone` | `oidc` | `cargo test -p uselesskey-cli --all-features bundle` |
| `jwt_missing_kid` | `implemented` | `NegativeToken::MissingKid` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_mismatched_kid` | `implemented` | `NegativeToken::MismatchedKid` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_expired` | `implemented` | `NegativeToken::ExpiredClaims` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_not_yet_valid` | `implemented` | `NegativeToken::NotYetValidClaims` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_bad_issuer` | `implemented` | `NegativeToken::BadIssuer` | no | `cargo test -p uselesskey-token --all-features` |
| `jwt_bad_audience` | `implemented` | `NegativeToken::BadAudience` | `oidc` | `cargo test -p uselesskey-cli --all-features bundle` |
| `token_malformed_bearer` | `implemented` | `NegativeToken::MalformedBearer` | no | `cargo test -p uselesskey-token --all-features` |
| `token_near_miss` | `implemented` | `NegativeToken::NearMissApiKey` | `scanner-safe` | `cargo test -p uselesskey-cli --all-features bundle` |

## Webhook

| Stable ID | Status | Public surface | Bundle exposed | Proof |
| --- | --- | --- | --- | --- |
| `webhook_near_miss_signature` | `accepted_planned` | none yet | no | taxonomy only |
| `webhook_tampered_body` | `implemented` | `uselesskey bundle --profile webhook` | `webhook` | `cargo test -p uselesskey-cli --all-features webhook` |
| `webhook_wrong_secret` | `implemented` | `uselesskey bundle --profile webhook` | `webhook` | `cargo test -p uselesskey-cli --all-features webhook` |
| `webhook_stale_timestamp` | `implemented` | `uselesskey bundle --profile webhook` | `webhook` | `cargo test -p uselesskey-cli --all-features webhook` |
| `webhook_missing_signature` | `implemented` | `uselesskey bundle --profile webhook` | `webhook` | `cargo test -p uselesskey-cli --all-features webhook` |
| `webhook_malformed_signature` | `implemented` | `uselesskey bundle --profile webhook` | `webhook` | `cargo test -p uselesskey-cli --all-features webhook` |
| `webhook_malformed_canonical_payload` | `accepted_planned` | none yet | no | taxonomy only |

## X.509 / TLS

| Stable ID | Status | Public surface | Bundle exposed | Proof |
| --- | --- | --- | --- | --- |
| `x509_expired_leaf` | `implemented` | `ChainNegative::ExpiredLeaf` | `tls` | `cargo test -p uselesskey-cli --all-features tls` |
| `x509_not_yet_valid_leaf` | `implemented` | `ChainNegative::NotYetValidLeaf` | `tls` | `cargo test -p uselesskey-cli --all-features tls` |
| `x509_wrong_hostname` | `implemented` | `ChainNegative::HostnameMismatch` | `tls` | `cargo test -p uselesskey-cli --all-features tls` |
| `x509_untrusted_root` | `implemented` | `ChainNegative::UnknownCa` | `tls` | `cargo test -p uselesskey-cli --all-features tls` |
| `x509_revoked_leaf` | `implemented` | `ChainNegative::RevokedLeaf` | no | `cargo test -p uselesskey-x509 --all-features` |
| `x509_invalid_key_usage` | `implemented` | `X509Negative::WrongKeyUsage` | no | `cargo test -p uselesskey-x509 --all-features` |

## Boundary

Implemented means `uselesskey` exposes a deterministic fixture class and proof
path. It does not prove provider compatibility, production security, scanner
evasion, release readiness, or downstream verifier correctness.
