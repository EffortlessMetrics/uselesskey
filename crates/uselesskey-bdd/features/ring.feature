@ring
Feature: ring adapter integration
  As a test author
  I want to convert uselesskey fixtures to ring types
  So that I can use test fixtures with code that depends on ring

  # --- RSA ---

  Scenario: convert RSA key to ring key pair
    Given a deterministic factory seeded with "ring-rsa-test"
    When I generate an RSA key for label "ring-rsa"
    Then the RSA key should convert to a valid ring key pair

  Scenario: deterministic RSA produces consistent ring key pairs
    Given a deterministic factory seeded with "ring-rsa-det"
    When I generate an RSA key for label "ring-rsa-det"
    Then the ring RSA key pairs from the same seed should have equal modulus length

  # --- ECDSA ---

  Scenario: convert ECDSA P-256 key to ring key pair
    Given a deterministic factory seeded with "ring-ecdsa-p256"
    When I generate an ECDSA ES256 key for label "ring-ecdsa-p256"
    Then the ECDSA key should convert to a valid ring ECDSA key pair

  Scenario: convert ECDSA P-384 key to ring key pair
    Given a deterministic factory seeded with "ring-ecdsa-p384"
    When I generate an ECDSA ES384 key for label "ring-ecdsa-p384"
    Then the ECDSA key should convert to a valid ring ECDSA key pair

  # --- Ed25519 ---

  Scenario: convert Ed25519 key to ring key pair
    Given a deterministic factory seeded with "ring-ed25519-test"
    When I generate an Ed25519 key for label "ring-ed25519"
    Then the Ed25519 key should convert to a valid ring Ed25519 key pair
