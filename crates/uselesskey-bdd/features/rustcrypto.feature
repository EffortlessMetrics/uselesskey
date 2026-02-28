@rustcrypto
Feature: RustCrypto adapter integration
  As a test author
  I want to use uselesskey fixtures with RustCrypto libraries
  So that I can test RustCrypto-based signing and verification

  Scenario: RSA key converts to RustCrypto types and signs
    Given a deterministic factory seeded with "rc-rsa-test"
    When I generate an RSA key for label "rc-rsa"
    And I sign and verify test data using the RustCrypto RSA adapter
    Then the adapter round-trip should succeed

  Scenario: ECDSA P-256 key converts to RustCrypto types and signs
    Given a deterministic factory seeded with "rc-p256-test"
    When I generate an ECDSA ES256 key for label "rc-p256"
    And I sign and verify test data using the RustCrypto ECDSA P-256 adapter
    Then the adapter round-trip should succeed

  Scenario: ECDSA P-384 key converts to RustCrypto types and signs
    Given a deterministic factory seeded with "rc-p384-test"
    When I generate an ECDSA ES384 key for label "rc-p384"
    And I sign and verify test data using the RustCrypto ECDSA P-384 adapter
    Then the adapter round-trip should succeed

  Scenario: Ed25519 key converts to RustCrypto types and signs
    Given a deterministic factory seeded with "rc-ed25519-test"
    When I generate an Ed25519 key for label "rc-ed25519"
    And I sign and verify test data using the RustCrypto Ed25519 adapter
    Then the adapter round-trip should succeed

  Scenario: HMAC key produces valid MAC with RustCrypto
    Given a deterministic factory seeded with "rc-hmac-test"
    When I generate an HMAC HS256 secret for label "rc-hmac"
    And I compute and verify a HMAC-SHA256 tag using the RustCrypto adapter
    Then the adapter round-trip should succeed
