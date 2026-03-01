@rustcrypto
Feature: RustCrypto adapter integration
  As a test author
  I want to convert uselesskey fixtures to RustCrypto ecosystem types
  So that I can use test fixtures with code that depends on rsa, p256, p384, ed25519-dalek, and hmac

  # --- RSA ---

  Scenario: convert RSA key to RustCrypto types
    Given a deterministic factory seeded with "rustcrypto-rsa-test"
    When I generate an RSA key for label "rustcrypto-rsa"
    Then the RSA key should convert to valid RustCrypto RSA types

  Scenario: RustCrypto RSA sign and verify
    Given a deterministic factory seeded with "rustcrypto-rsa-signverify"
    When I generate an RSA key for label "rustcrypto-rsa-sv"
    Then the RustCrypto RSA types should sign and verify

  # --- ECDSA P-256 ---

  Scenario: convert ECDSA P-256 key to RustCrypto types
    Given a deterministic factory seeded with "rustcrypto-p256-test"
    When I generate an ECDSA ES256 key for label "rustcrypto-p256"
    Then the ECDSA ES256 key should convert to a valid P-256 signing key

  Scenario: RustCrypto P-256 sign and verify
    Given a deterministic factory seeded with "rustcrypto-p256-signverify"
    When I generate an ECDSA ES256 key for label "rustcrypto-p256-sv"
    Then the RustCrypto P-256 types should sign and verify

  # --- ECDSA P-384 ---

  Scenario: convert ECDSA P-384 key to RustCrypto types
    Given a deterministic factory seeded with "rustcrypto-p384-test"
    When I generate an ECDSA ES384 key for label "rustcrypto-p384"
    Then the ECDSA ES384 key should convert to a valid P-384 signing key

  Scenario: RustCrypto P-384 sign and verify
    Given a deterministic factory seeded with "rustcrypto-p384-signverify"
    When I generate an ECDSA ES384 key for label "rustcrypto-p384-sv"
    Then the RustCrypto P-384 types should sign and verify

  # --- Ed25519 ---

  Scenario: convert Ed25519 key to ed25519-dalek types
    Given a deterministic factory seeded with "rustcrypto-ed25519-test"
    When I generate an Ed25519 key for label "rustcrypto-ed25519"
    Then the Ed25519 key should convert to a valid ed25519-dalek signing key

  Scenario: RustCrypto Ed25519 sign and verify
    Given a deterministic factory seeded with "rustcrypto-ed25519-signverify"
    When I generate an Ed25519 key for label "rustcrypto-ed25519-sv"
    Then the RustCrypto Ed25519 types should sign and verify

  # --- HMAC ---

  Scenario: convert HMAC HS256 secret to RustCrypto HMAC
    Given a deterministic factory seeded with "rustcrypto-hmac-test"
    When I generate an HMAC HS256 secret for label "rustcrypto-hmac"
    Then the HMAC secret should convert to a valid RustCrypto HMAC-SHA256

  Scenario: convert HMAC HS384 secret to RustCrypto HMAC
    Given a deterministic factory seeded with "rustcrypto-hmac384-test"
    When I generate an HMAC HS384 secret for label "rustcrypto-hmac384"
    Then the HMAC secret should convert to a valid RustCrypto HMAC-SHA384

  Scenario: convert HMAC HS512 secret to RustCrypto HMAC
    Given a deterministic factory seeded with "rustcrypto-hmac512-test"
    When I generate an HMAC HS512 secret for label "rustcrypto-hmac512"
    Then the HMAC secret should convert to a valid RustCrypto HMAC-SHA512
