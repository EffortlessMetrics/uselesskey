Feature: ring adapter
  As a test author
  I want to convert uselesskey fixtures into ring types
  So that I can use test fixtures with code that depends on ring

  # --- RSA sign and verify ---

  @ring
  Scenario: ring RSA key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "ring-rsa-test"
    When I generate an RSA key for label "ring-rsa"
    And I sign a message with the ring RSA key
    Then the ring RSA signature should verify

  @ring
  Scenario: ring RSA wrong-key rejection
    Given a deterministic factory seeded with "ring-rsa-wrong"
    When I generate an RSA key for label "ring-rsa-signer"
    And I sign a message with the ring RSA key
    And I generate another RSA key for label "ring-rsa-wrong"
    Then the ring RSA signature should not verify with the other key

  # --- ECDSA P-256 sign and verify ---

  @ring
  Scenario: ring ECDSA P-256 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "ring-p256-test"
    When I generate an ECDSA ES256 key for label "ring-p256"
    And I sign a message with the ring ECDSA P-256 key
    Then the ring ECDSA P-256 signature should verify

  @ring
  Scenario: ring ECDSA P-384 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "ring-p384-test"
    When I generate an ECDSA ES384 key for label "ring-p384"
    And I sign a message with the ring ECDSA P-384 key
    Then the ring ECDSA P-384 signature should verify

  # --- Ed25519 sign and verify ---

  @ring
  Scenario: ring Ed25519 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "ring-ed25519-test"
    When I generate an Ed25519 key for label "ring-ed25519"
    And I sign a message with the ring Ed25519 key
    Then the ring Ed25519 signature should verify

  @ring
  Scenario: ring Ed25519 wrong-key rejection
    Given a deterministic factory seeded with "ring-ed25519-wrong"
    When I generate an Ed25519 key for label "ring-ed25519-signer"
    And I sign a message with the ring Ed25519 key
    And I generate another Ed25519 key for label "ring-ed25519-wrong"
    Then the ring Ed25519 signature should not verify with the other key
