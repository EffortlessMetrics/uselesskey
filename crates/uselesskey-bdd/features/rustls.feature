@rustls
Feature: rustls adapter integration
  As a test author
  I want to use uselesskey fixtures with rustls
  So that I can test TLS configurations without real certificates

  Scenario: X.509 self-signed certificate converts to rustls types
    Given a deterministic factory seeded with "rustls-x509-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "rustls-cert"
    And I convert the X.509 certificate to rustls types
    Then the rustls certificate DER should be non-empty
    And the rustls private key DER should be non-empty

  Scenario: X.509 chain converts to rustls chain
    Given a deterministic factory seeded with "rustls-chain-test"
    When I generate a certificate chain for domain "test.example.com" with label "rustls-chain"
    And I convert the certificate chain to rustls types
    Then the rustls chain should have 2 certificates
    And the rustls root certificate should be non-empty

  Scenario: RSA key pair converts to rustls private key
    Given a deterministic factory seeded with "rustls-rsa-test"
    When I generate an RSA key for label "rustls-rsa"
    And I convert the key pair to a rustls PrivateKeyDer
    Then the rustls private key DER should be non-empty

  Scenario: ECDSA key pair converts to rustls private key
    Given a deterministic factory seeded with "rustls-ecdsa-test"
    When I generate an ECDSA ES256 key for label "rustls-ecdsa"
    And I convert the ECDSA key pair to a rustls PrivateKeyDer
    Then the rustls private key DER should be non-empty

  Scenario: Ed25519 key pair converts to rustls private key
    Given a deterministic factory seeded with "rustls-ed25519-test"
    When I generate an Ed25519 key for label "rustls-ed25519"
    And I convert the Ed25519 key pair to a rustls PrivateKeyDer
    Then the rustls private key DER should be non-empty
