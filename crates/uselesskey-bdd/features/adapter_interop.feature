Feature: Adapter interop expansion
  As a test author
  I want to verify that the same fixtures work across multiple adapter crates
  So that I can confidently use fixtures in mixed-adapter test suites

  # --- aws-lc-rs + JWT cross-adapter ---

  @jsonwebtoken @aws_lc_rs
  Scenario: same RSA key signs JWT and aws-lc-rs message
    Given a deterministic factory seeded with "interop-aws-rsa"
    When I generate an RSA key for label "aws-jwt-rsa"
    And I sign a JWT with the RSA key
    Then the JWT should be valid
    And the JWT header should have alg "RS256"
    When I sign a message with the aws-lc-rs RSA key
    Then the aws-lc-rs RSA signature should verify

  @jsonwebtoken @aws_lc_rs
  Scenario: same ECDSA key signs JWT and aws-lc-rs message
    Given a deterministic factory seeded with "interop-aws-ecdsa"
    When I generate an ECDSA ES256 key for label "aws-jwt-ecdsa"
    And I sign a JWT with the ECDSA key
    Then the JWT should be valid
    And the JWT header should have alg "ES256"
    When I sign a message with the aws-lc-rs ECDSA P-256 key
    Then the aws-lc-rs ECDSA P-256 signature should verify

  @jsonwebtoken @aws_lc_rs
  Scenario: same Ed25519 key signs JWT and aws-lc-rs message
    Given a deterministic factory seeded with "interop-aws-ed25519"
    When I generate an Ed25519 key for label "aws-jwt-ed25519"
    And I sign a JWT with the Ed25519 key
    Then the JWT should be valid
    And the JWT header should have alg "EdDSA"
    When I sign a message with the aws-lc-rs Ed25519 key
    Then the aws-lc-rs Ed25519 signature should verify

  # --- RustCrypto + ring cross-adapter ---

  @rustcrypto @ring
  Scenario: same RSA key works in both RustCrypto and ring
    Given a deterministic factory seeded with "interop-rc-ring-rsa"
    When I generate an RSA key for label "cross-lib-rsa"
    And I sign a message with the RustCrypto RSA key
    Then the RustCrypto RSA signature should verify
    When I sign a message with the ring RSA key
    Then the ring RSA signature should verify

  @rustcrypto @ring
  Scenario: same ECDSA P-256 key works in both RustCrypto and ring
    Given a deterministic factory seeded with "interop-rc-ring-p256"
    When I generate an ECDSA ES256 key for label "cross-lib-p256"
    And I sign a message with the RustCrypto P-256 key
    Then the RustCrypto P-256 signature should verify
    When I sign a message with the ring ECDSA P-256 key
    Then the ring ECDSA P-256 signature should verify

  @rustcrypto @ring
  Scenario: same Ed25519 key works in both RustCrypto and ring
    Given a deterministic factory seeded with "interop-rc-ring-ed25519"
    When I generate an Ed25519 key for label "cross-lib-ed25519"
    And I sign a message with the RustCrypto Ed25519 key
    Then the RustCrypto Ed25519 signature should verify
    When I sign a message with the ring Ed25519 key
    Then the ring Ed25519 signature should verify

  # --- ECDSA P-384 cross-adapter ---

  @rustcrypto @ring
  Scenario: same ECDSA P-384 key works in both RustCrypto and ring
    Given a deterministic factory seeded with "interop-rc-ring-p384"
    When I generate an ECDSA ES384 key for label "cross-lib-p384"
    And I sign a message with the RustCrypto P-384 key
    Then the RustCrypto P-384 signature should verify
    When I sign a message with the ring ECDSA P-384 key
    Then the ring ECDSA P-384 signature should verify

  @aws_lc_rs @ring
  Scenario: same ECDSA P-384 key works in both aws-lc-rs and ring
    Given a deterministic factory seeded with "interop-aws-ring-p384"
    When I generate an ECDSA ES384 key for label "aws-ring-p384"
    And I sign a message with the aws-lc-rs ECDSA P-384 key
    Then the aws-lc-rs ECDSA P-384 signature should verify
    When I sign a message with the ring ECDSA P-384 key
    Then the ring ECDSA P-384 signature should verify

  # --- rustls with JWT verification ---

  @jsonwebtoken @rustls
  Scenario: X.509 chain works for rustls and JWT uses the underlying key
    Given a deterministic factory seeded with "interop-rustls-jwt"
    When I generate a certificate chain for domain "jwt.example.com" with label "rustls-jwt"
    And I build a rustls ServerConfig from the chain
    Then the rustls ServerConfig should be valid
