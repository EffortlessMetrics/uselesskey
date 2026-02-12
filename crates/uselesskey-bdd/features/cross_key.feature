Feature: Cross-key validation failures
  As a test author
  I want to verify that wrong key types fail validation
  So that I can test error handling in cryptographic workflows

  # --- RSA vs ECDSA ---

  Scenario: RSA key has different JWK kty than ECDSA key
    Given a deterministic factory seeded with "cross-rsa-ecdsa-test"
    When I generate an RSA key for label "cross-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "cross-ecdsa"
    Then the RSA JWK should have kty "RSA"
    And the ECDSA JWK should have kty "EC"
    And the RSA JWK kty should differ from the ECDSA JWK kty

  Scenario: ECDSA key has different curve than expected
    Given a deterministic factory seeded with "cross-curve-test"
    When I generate an ECDSA ES256 key for label "p256-key"
    And I generate an ECDSA ES384 key for label "p384-key"
    Then the ES256 JWK should have crv "P-256"
    And the ES384 JWK should have crv "P-384"
    And the ES256 crv should differ from the ES384 crv

  # --- Key ID uniqueness ---

  Scenario: different key types have different kids
    Given a deterministic factory seeded with "cross-kid-test"
    When I generate an RSA key for label "kid-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "kid-ecdsa"
    And I generate an Ed25519 key for label "kid-ed25519"
    And I generate an HMAC HS256 secret for label "kid-hmac"
    Then each key should have a unique kid

  # --- Algorithm mismatch ---

  Scenario: RSA key with RS256 spec has correct alg in JWK
    Given a deterministic factory seeded with "cross-alg-test"
    When I generate an RSA key for label "alg-rsa256" with spec RS256
    And I generate an RSA key for label "alg-rsa384" with spec RS384
    Then the RS256 JWK should have alg "RS256"
    And the RS384 JWK should have alg "RS384"
    And the RS256 alg should differ from the RS384 alg

  Scenario: HMAC key with HS256 spec has correct alg in JWK
    Given a deterministic factory seeded with "cross-hmac-alg-test"
    When I generate an HMAC HS256 secret for label "hmac256"
    And I generate an HMAC HS384 secret for label "hmac384"
    And I generate an HMAC HS512 secret for label "hmac512"
    Then the HS256 JWK should have alg "HS256"
    And the HS384 JWK should have alg "HS384"
    And the HS512 JWK should have alg "HS512"

  # --- Key size differences ---

  Scenario: different RSA key sizes produce different JWK n values
    Given a deterministic factory seeded with "cross-rsa-size-test"
    When I generate an RSA key for label "rsa-2048" with spec 2048
    And I generate an RSA key for label "rsa-3072" with spec 3072
    And I generate an RSA key for label "rsa-4096" with spec 4096
    Then the RSA 2048 n value should have different length than RSA 4096 n value

  # --- Deterministic isolation ---

  Scenario: generating one key type does not affect another
    Given a deterministic factory seeded with "cross-isolation-test"
    When I generate an RSA key for label "isolation-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "isolation-ecdsa"
    And I generate an Ed25519 key for label "isolation-ed25519"
    And I clear the factory cache
    And I generate the same keys again in reverse order
    Then each regenerated key should be identical to the original

  # --- JWKS key type filtering ---

  Scenario: JWKS can contain mixed key types
    Given a deterministic factory seeded with "cross-jwks-mixed-test"
    When I generate an RSA key for label "mixed-rsa" with spec RS256
    And I generate an ECDSA ES256 key for label "mixed-ecdsa"
    And I generate an Ed25519 key for label "mixed-ed25519"
    And I build a JWKS containing all three keys
    Then the JWKS should contain a key with alg "RS256"
    And the JWKS should contain a key with alg "ES256"
    And the JWKS should contain a key with alg "EdDSA"
