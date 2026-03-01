@aws_lc_rs
Feature: aws-lc-rs adapter integration
  As a test author
  I want to convert uselesskey fixtures to aws-lc-rs types
  So that I can use test fixtures with code that depends on aws-lc-rs

  # --- RSA ---

  Scenario: convert RSA key to aws-lc-rs key pair
    Given a deterministic factory seeded with "aws-lc-rsa-test"
    When I generate an RSA key for label "aws-lc-rsa"
    Then the RSA key should convert to a valid aws-lc-rs key pair

  Scenario: deterministic RSA produces consistent aws-lc-rs key pairs
    Given a deterministic factory seeded with "aws-lc-rsa-det"
    When I generate an RSA key for label "aws-lc-rsa-det"
    Then the aws-lc-rs RSA key pairs from the same seed should have equal modulus length

  # --- ECDSA ---

  Scenario: convert ECDSA P-256 key to aws-lc-rs key pair
    Given a deterministic factory seeded with "aws-lc-ecdsa-p256"
    When I generate an ECDSA ES256 key for label "aws-lc-ecdsa-p256"
    Then the ECDSA key should convert to a valid aws-lc-rs ECDSA key pair

  Scenario: convert ECDSA P-384 key to aws-lc-rs key pair
    Given a deterministic factory seeded with "aws-lc-ecdsa-p384"
    When I generate an ECDSA ES384 key for label "aws-lc-ecdsa-p384"
    Then the ECDSA key should convert to a valid aws-lc-rs ECDSA key pair

  # --- Ed25519 ---

  Scenario: convert Ed25519 key to aws-lc-rs key pair
    Given a deterministic factory seeded with "aws-lc-ed25519-test"
    When I generate an Ed25519 key for label "aws-lc-ed25519"
    Then the Ed25519 key should convert to a valid aws-lc-rs Ed25519 key pair
