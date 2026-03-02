Feature: rustls adapter
  As a test author
  I want to convert uselesskey fixtures into rustls types
  So that I can use test fixtures with code that depends on rustls

  # --- Certificate and key conversion ---

  @rustls
  Scenario: rustls certificate DER conversion from X.509
    Given a deterministic factory seeded with "rustls-cert-test"
    When I generate an X.509 certificate for domain "example.com" with label "rustls-cert"
    And I convert the X.509 certificate to rustls CertificateDer
    Then the rustls CertificateDer should not be empty

  @rustls
  Scenario: rustls private key DER conversion from X.509
    Given a deterministic factory seeded with "rustls-key-test"
    When I generate an X.509 certificate for domain "example.com" with label "rustls-key"
    And I convert the X.509 private key to rustls PrivateKeyDer
    Then the rustls PrivateKeyDer should not be empty

  # --- Server config ---

  @rustls
  Scenario: rustls ServerConfig from certificate chain
    Given a deterministic factory seeded with "rustls-server-test"
    When I generate a certificate chain for domain "example.com" with label "rustls-server"
    And I build a rustls ServerConfig from the chain
    Then the rustls ServerConfig should be valid

  # --- Client config ---

  @rustls
  Scenario: rustls ClientConfig from certificate chain
    Given a deterministic factory seeded with "rustls-client-test"
    When I generate a certificate chain for domain "example.com" with label "rustls-client"
    And I build a rustls ClientConfig from the chain
    Then the rustls ClientConfig should be valid

  # --- Chain conversion ---

  @rustls
  Scenario: rustls chain DER conversion includes leaf and intermediate
    Given a deterministic factory seeded with "rustls-chain-test"
    When I generate a certificate chain for domain "example.com" with label "rustls-chain"
    And I convert the chain to rustls CertificateDer list
    Then the rustls chain should have at least 2 certificates

  @rustls
  Scenario: rustls root certificate DER conversion
    Given a deterministic factory seeded with "rustls-root-test"
    When I generate a certificate chain for domain "example.com" with label "rustls-root"
    And I convert the chain root to rustls CertificateDer
    Then the rustls root CertificateDer should not be empty
