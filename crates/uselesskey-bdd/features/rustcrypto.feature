Feature: RustCrypto adapter
  As a test author
  I want to convert uselesskey fixtures into RustCrypto types
  So that I can use test fixtures with code that depends on the RustCrypto crates

  # --- RSA sign and verify ---

  @rustcrypto
  Scenario: RustCrypto RSA sign and verify round-trip
    Given a deterministic factory seeded with "rustcrypto-rsa-test"
    When I generate an RSA key for label "rustcrypto-rsa"
    And I sign a message with the RustCrypto RSA key
    Then the RustCrypto RSA signature should verify

  @rustcrypto
  Scenario: RustCrypto RSA wrong-key rejection
    Given a deterministic factory seeded with "rustcrypto-rsa-wrong"
    When I generate an RSA key for label "rustcrypto-rsa-signer"
    And I sign a message with the RustCrypto RSA key
    And I generate another RSA key for label "rustcrypto-rsa-wrong"
    Then the RustCrypto RSA signature should not verify with the other key

  # --- ECDSA P-256 sign and verify ---

  @rustcrypto
  Scenario: RustCrypto ECDSA P-256 sign and verify round-trip
    Given a deterministic factory seeded with "rustcrypto-p256-test"
    When I generate an ECDSA ES256 key for label "rustcrypto-p256"
    And I sign a message with the RustCrypto P-256 key
    Then the RustCrypto P-256 signature should verify

  @rustcrypto
  Scenario: RustCrypto ECDSA P-256 wrong-key rejection
    Given a deterministic factory seeded with "rustcrypto-p256-wrong"
    When I generate an ECDSA ES256 key for label "rustcrypto-p256-signer"
    And I sign a message with the RustCrypto P-256 key
    And I generate another ECDSA ES256 key for label "rustcrypto-p256-wrong"
    Then the RustCrypto P-256 signature should not verify with the other key

  # --- ECDSA P-384 sign and verify ---

  @rustcrypto
  Scenario: RustCrypto ECDSA P-384 sign and verify round-trip
    Given a deterministic factory seeded with "rustcrypto-p384-test"
    When I generate an ECDSA ES384 key for label "rustcrypto-p384"
    And I sign a message with the RustCrypto P-384 key
    Then the RustCrypto P-384 signature should verify

  @rustcrypto
  Scenario: RustCrypto ECDSA P-384 wrong-key rejection
    Given a deterministic factory seeded with "rustcrypto-p384-wrong"
    When I generate an ECDSA ES384 key for label "rustcrypto-p384-signer"
    And I sign a message with the RustCrypto P-384 key
    And I generate another ECDSA ES384 key for label "rustcrypto-p384-wrong"
    Then the RustCrypto P-384 signature should not verify with the other key

  # --- Ed25519 sign and verify ---

  @rustcrypto
  Scenario: RustCrypto Ed25519 sign and verify round-trip
    Given a deterministic factory seeded with "rustcrypto-ed25519-test"
    When I generate an Ed25519 key for label "rustcrypto-ed25519"
    And I sign a message with the RustCrypto Ed25519 key
    Then the RustCrypto Ed25519 signature should verify

  @rustcrypto
  Scenario: RustCrypto Ed25519 wrong-key rejection
    Given a deterministic factory seeded with "rustcrypto-ed25519-wrong"
    When I generate an Ed25519 key for label "rustcrypto-ed25519-signer"
    And I sign a message with the RustCrypto Ed25519 key
    And I generate another Ed25519 key for label "rustcrypto-ed25519-wrong"
    Then the RustCrypto Ed25519 signature should not verify with the other key

  # --- HMAC tag generation ---

  @rustcrypto
  Scenario: RustCrypto HMAC SHA-256 tag generation and verification
    Given a deterministic factory seeded with "rustcrypto-hmac256-test"
    When I generate an HMAC HS256 secret for label "rustcrypto-hmac"
    And I compute a RustCrypto HMAC-SHA256 tag
    Then the RustCrypto HMAC-SHA256 tag should verify

  @rustcrypto
  Scenario: RustCrypto HMAC SHA-384 tag generation and verification
    Given a deterministic factory seeded with "rustcrypto-hmac384-test"
    When I generate an HMAC HS384 secret for label "rustcrypto-hmac384"
    And I compute a RustCrypto HMAC-SHA384 tag
    Then the RustCrypto HMAC-SHA384 tag should verify

  @rustcrypto
  Scenario: RustCrypto HMAC SHA-512 tag generation and verification
    Given a deterministic factory seeded with "rustcrypto-hmac512-test"
    When I generate an HMAC HS512 secret for label "rustcrypto-hmac512"
    And I compute a RustCrypto HMAC-SHA512 tag
    Then the RustCrypto HMAC-SHA512 tag should verify
