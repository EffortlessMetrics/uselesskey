Feature: Cross-adapter verification
  As a test author
  I want to verify that the same key works across different adapters
  So that I can mix adapter libraries in my test infrastructure

  @ring
  Scenario: RSA key is usable via both jsonwebtoken and ring
    Given a deterministic factory seeded with "cross-jwt-ring-rsa"
    When I generate an RSA key for label "cross-rsa"
    And I sign a JWT with the RSA key
    And I sign and verify test data using the ring RSA adapter
    Then the JWT should be valid
    And the adapter round-trip should succeed

  @ring
  Scenario: ECDSA key is usable via both jsonwebtoken and ring
    Given a deterministic factory seeded with "cross-jwt-ring-ecdsa"
    When I generate an ECDSA ES256 key for label "cross-ecdsa"
    And I sign a JWT with the ECDSA key
    And I sign and verify test data using the ring ECDSA adapter
    Then the JWT should be valid
    And the adapter round-trip should succeed

  @ring
  Scenario: Ed25519 key is usable via both jsonwebtoken and ring
    Given a deterministic factory seeded with "cross-jwt-ring-ed25519"
    When I generate an Ed25519 key for label "cross-ed25519"
    And I sign a JWT with the Ed25519 key
    And I sign and verify test data using the ring Ed25519 adapter
    Then the JWT should be valid
    And the adapter round-trip should succeed

  @rustcrypto
  Scenario: RSA key is usable via both jsonwebtoken and RustCrypto
    Given a deterministic factory seeded with "cross-jwt-rc-rsa"
    When I generate an RSA key for label "cross-rc-rsa"
    And I sign a JWT with the RSA key
    And I sign and verify test data using the RustCrypto RSA adapter
    Then the JWT should be valid
    And the adapter round-trip should succeed

  @rustcrypto
  Scenario: HMAC key is usable via both jsonwebtoken and RustCrypto
    Given a deterministic factory seeded with "cross-jwt-rc-hmac"
    When I generate an HMAC HS256 secret for label "cross-rc-hmac"
    And I sign a JWT with the HMAC key
    And I compute and verify a HMAC-SHA256 tag using the RustCrypto adapter
    Then the JWT should be valid
    And the adapter round-trip should succeed

  @rustls
  Scenario: X.509 chain is usable via both core API and rustls
    Given a deterministic factory seeded with "cross-rustls-chain"
    When I generate a certificate chain for domain "test.example.com" with label "cross-chain"
    And I convert the certificate chain to rustls types
    Then the certificate chain should have a leaf certificate
    And the certificate chain should have an intermediate certificate
    And the certificate chain should have a root certificate
    And the rustls chain should have 2 certificates
    And the rustls root certificate should be non-empty
