@rustls
Feature: rustls adapter integration
  As a test author
  I want to convert uselesskey fixtures to rustls-pki-types
  So that I can set up TLS test scenarios with uselesskey keys

  # --- Private key conversions ---

  Scenario: convert RSA key to rustls PrivateKeyDer
    Given a deterministic factory seeded with "rustls-rsa-test"
    When I generate an RSA key for label "rustls-rsa"
    Then the RSA key should convert to a valid rustls PrivateKeyDer
    And the rustls PrivateKeyDer should match the RSA PKCS8 DER

  Scenario: convert ECDSA key to rustls PrivateKeyDer
    Given a deterministic factory seeded with "rustls-ecdsa-test"
    When I generate an ECDSA ES256 key for label "rustls-ecdsa"
    Then the ECDSA key should convert to a valid rustls PrivateKeyDer

  Scenario: convert ECDSA P-384 key to rustls PrivateKeyDer
    Given a deterministic factory seeded with "rustls-ecdsa-p384"
    When I generate an ECDSA ES384 key for label "rustls-ecdsa-p384"
    Then the ECDSA key should convert to a valid rustls PrivateKeyDer

  Scenario: convert Ed25519 key to rustls PrivateKeyDer
    Given a deterministic factory seeded with "rustls-ed25519-test"
    When I generate an Ed25519 key for label "rustls-ed25519"
    Then the Ed25519 key should convert to a valid rustls PrivateKeyDer

  # --- X.509 self-signed cert ---

  Scenario: convert X.509 self-signed cert to rustls types
    Given a deterministic factory seeded with "rustls-x509-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "rustls-x509"
    Then the X.509 cert should convert to a valid rustls CertificateDer
    And the X.509 cert rustls CertificateDer should match the cert DER
    And the X.509 cert should convert to a valid rustls PrivateKeyDer

  # --- X.509 chain ---

  Scenario: convert X.509 chain to rustls types
    Given a deterministic factory seeded with "rustls-chain-test"
    When I generate a certificate chain for domain "test.example.com" with label "rustls-chain"
    Then the X.509 chain should produce 2 rustls certificate DERs
    And the X.509 chain should produce a rustls root certificate
    And the X.509 chain rustls root should match the root DER
