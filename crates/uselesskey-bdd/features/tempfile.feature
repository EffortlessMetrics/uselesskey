Feature: Tempfile artifacts
  As a test author
  I want to write keys to temporary files
  So that I can pass file paths to external tools

  Background:
    Given a deterministic factory seeded with "tempfile-test"
    And I generate an RSA key for label "file-test"

  Scenario: write private key PKCS8 PEM to tempfile
    When I write the private key to a tempfile
    Then the tempfile path should end with ".pkcs8.pem"
    And reading the tempfile should match the private key PEM

  Scenario: write public key SPKI PEM to tempfile
    When I write the public key to a tempfile
    Then the tempfile path should end with ".spki.pem"
    And reading the tempfile should match the public key PEM
