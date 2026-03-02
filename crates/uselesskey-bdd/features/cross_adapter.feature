Feature: Cross-adapter fixture sharing
  As a test author
  I want to verify the same deterministic fixture works across multiple adapter crates
  So that I can mix and match adapters in the same test suite

  # --- RSA key used in JWT then ring ---

  @jsonwebtoken @ring
  Scenario: same RSA key signs JWT and ring message
    Given a deterministic factory seeded with "cross-adapter-rsa"
    When I generate an RSA key for label "cross-rsa"
    And I sign a JWT with the RSA key
    Then the JWT should be valid
    And the JWT header should have alg "RS256"
    When I sign a message with the ring RSA key
    Then the ring RSA signature should verify

  # --- ECDSA key used in JWT then RustCrypto ---

  @jsonwebtoken @rustcrypto
  Scenario: same ECDSA key signs JWT and RustCrypto message
    Given a deterministic factory seeded with "cross-adapter-ecdsa"
    When I generate an ECDSA ES256 key for label "cross-ecdsa"
    And I sign a JWT with the ECDSA key
    Then the JWT should be valid
    And the JWT header should have alg "ES256"
    When I sign a message with the RustCrypto P-256 key
    Then the RustCrypto P-256 signature should verify

  # --- Ed25519 key used in JWT then ring ---

  @jsonwebtoken @ring
  Scenario: same Ed25519 key signs JWT and ring message
    Given a deterministic factory seeded with "cross-adapter-ed25519"
    When I generate an Ed25519 key for label "cross-ed25519"
    And I sign a JWT with the Ed25519 key
    Then the JWT should be valid
    And the JWT header should have alg "EdDSA"
    When I sign a message with the ring Ed25519 key
    Then the ring Ed25519 signature should verify

  # --- HMAC key used in JWT then RustCrypto ---

  @jsonwebtoken @rustcrypto
  Scenario: same HMAC key signs JWT and RustCrypto HMAC tag
    Given a deterministic factory seeded with "cross-adapter-hmac"
    When I generate an HMAC HS256 secret for label "cross-hmac"
    And I sign a JWT with the HMAC key
    Then the JWT should be valid
    And the JWT header should have alg "HS256"
    When I compute a RustCrypto HMAC-SHA256 tag
    Then the RustCrypto HMAC-SHA256 tag should verify

  # --- X.509 chain used in rustls ServerConfig then ClientConfig ---

  @rustls
  Scenario: same X.509 chain works for rustls server and client config
    Given a deterministic factory seeded with "cross-adapter-rustls"
    When I generate a certificate chain for domain "example.com" with label "cross-rustls"
    And I build a rustls ServerConfig from the chain
    Then the rustls ServerConfig should be valid
    When I build a rustls ClientConfig from the chain
    Then the rustls ClientConfig should be valid

  # --- Deterministic key stability across adapters ---

  @jsonwebtoken @ring
  Scenario: deterministic RSA key produces same JWT across factory instances
    Given a deterministic factory seeded with "cross-adapter-det-rsa"
    When I generate an RSA key for label "det-cross-rsa"
    And I sign a JWT with the RSA key
    And I record the JWT token
    And I switch to a deterministic factory seeded with "cross-adapter-det-rsa"
    And I generate an RSA key for label "det-cross-rsa"
    And I sign a JWT with the RSA key
    Then the JWT token should be identical to the recorded one
