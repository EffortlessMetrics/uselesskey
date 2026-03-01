Feature: aws-lc-rs adapter
  As a test author
  I want to convert uselesskey fixtures into aws-lc-rs types
  So that I can use test fixtures with code that depends on aws-lc-rs

  # --- RSA sign and verify ---

  @aws_lc_rs
  Scenario: aws-lc-rs RSA key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "aws-lc-rsa-test"
    When I generate an RSA key for label "aws-lc-rsa"
    And I sign a message with the aws-lc-rs RSA key
    Then the aws-lc-rs RSA signature should verify

  @aws_lc_rs
  Scenario: aws-lc-rs RSA wrong-key rejection
    Given a deterministic factory seeded with "aws-lc-rsa-wrong"
    When I generate an RSA key for label "aws-lc-rsa-signer"
    And I sign a message with the aws-lc-rs RSA key
    And I generate another RSA key for label "aws-lc-rsa-wrong"
    Then the aws-lc-rs RSA signature should not verify with the other key

  # --- ECDSA P-256 sign and verify ---

  @aws_lc_rs
  Scenario: aws-lc-rs ECDSA P-256 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "aws-lc-p256-test"
    When I generate an ECDSA ES256 key for label "aws-lc-p256"
    And I sign a message with the aws-lc-rs ECDSA P-256 key
    Then the aws-lc-rs ECDSA P-256 signature should verify

  @aws_lc_rs
  Scenario: aws-lc-rs ECDSA P-384 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "aws-lc-p384-test"
    When I generate an ECDSA ES384 key for label "aws-lc-p384"
    And I sign a message with the aws-lc-rs ECDSA P-384 key
    Then the aws-lc-rs ECDSA P-384 signature should verify

  # --- Ed25519 sign and verify ---

  @aws_lc_rs
  Scenario: aws-lc-rs Ed25519 key conversion and sign/verify round-trip
    Given a deterministic factory seeded with "aws-lc-ed25519-test"
    When I generate an Ed25519 key for label "aws-lc-ed25519"
    And I sign a message with the aws-lc-rs Ed25519 key
    Then the aws-lc-rs Ed25519 signature should verify

  @aws_lc_rs
  Scenario: aws-lc-rs Ed25519 wrong-key rejection
    Given a deterministic factory seeded with "aws-lc-ed25519-wrong"
    When I generate an Ed25519 key for label "aws-lc-ed25519-signer"
    And I sign a message with the aws-lc-rs Ed25519 key
    And I generate another Ed25519 key for label "aws-lc-ed25519-wrong"
    Then the aws-lc-rs Ed25519 signature should not verify with the other key
