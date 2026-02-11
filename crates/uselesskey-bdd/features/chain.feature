Feature: X.509 certificate chain fixtures
  As a test author
  I want to generate X.509 certificate chains (Root CA → Intermediate → Leaf)
  So that I can test TLS certificate validation without committing real certificates

  # --- Determinism ---

  Scenario: deterministic certificate chains are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate a certificate chain for domain "test.example.com" with label "chain-server"
    And I generate a certificate chain for domain "test.example.com" with label "chain-server" again
    Then the leaf certificate PEM should be identical
    And the intermediate certificate PEM should be identical
    And the root certificate PEM should be identical

  Scenario: certificate chain derivation survives cache clear
    Given a deterministic factory seeded with "chain-seed-alpha"
    When I generate a certificate chain for domain "api.example.com" with label "first-chain"
    And I clear the factory cache
    And I generate a certificate chain for domain "api.example.com" with label "first-chain" again
    Then the leaf certificate PEM should be identical

  Scenario: different labels produce different certificate chains
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate a certificate chain for domain "test.example.com" with label "chain-a"
    And I generate another certificate chain for domain "test.example.com" with label "chain-b"
    Then the leaf certificates should have different DER
    And the root certificates should have different DER

  # --- Chain structure ---

  Scenario: certificate chain contains three certificates
    Given a deterministic factory seeded with "structure-test"
    When I generate a certificate chain for domain "test.example.com" with label "three-tier"
    Then the certificate chain should have a leaf certificate
    And the certificate chain should have an intermediate certificate
    And the certificate chain should have a root certificate

  Scenario: certificate chain PEM contains leaf and intermediate
    Given a deterministic factory seeded with "pem-test"
    When I generate a certificate chain for domain "test.example.com" with label "pem-check"
    Then the chain PEM should contain 2 "-----BEGIN CERTIFICATE-----" markers

  Scenario: certificate chain components are different
    Given a deterministic factory seeded with "different-test"
    When I generate a certificate chain for domain "test.example.com" with label "diff-check"
    Then the leaf certificate DER should differ from the intermediate certificate DER
    And the intermediate certificate DER should differ from the root certificate DER

  # --- Subject names ---

  Scenario: certificate chain has correct common names
    Given a deterministic factory seeded with "cn-chain-test"
    When I generate a certificate chain for domain "myservice.example.com" with label "cn-check"
    Then the leaf certificate should have common name "myservice.example.com"
    And the intermediate certificate should have a common name
    And the root certificate should have a common name

  # --- SANs ---

  Scenario: certificate chain supports multiple SANs
    Given a deterministic factory seeded with "san-chain-test"
    When I generate a certificate chain for domain "test.example.com" with label "san-check"
    And I add SAN "localhost" to the certificate chain
    And I add SAN "127.0.0.1" to the certificate chain
    Then the leaf certificate should contain SAN "test.example.com"
    And the leaf certificate should contain SAN "localhost"
    And the leaf certificate should contain SAN "127.0.0.1"

  # --- Private key ---

  Scenario: certificate chain has matching private key
    Given a deterministic factory seeded with "key-match-test"
    When I generate a certificate chain for domain "test.example.com" with label "key-check"
    Then the leaf private key should be a valid PKCS#8 key
    And the leaf private key should match the leaf certificate

  # --- Tempfile outputs ---

  Scenario: certificate chain writes to tempfiles
    Given a deterministic factory seeded with "tempfile-chain-test"
    When I generate a certificate chain for domain "test.example.com" with label "temp-chain"
    And I write the leaf certificate PEM to a tempfile
    And I write the leaf private key PEM to a tempfile
    Then the leaf certificate tempfile should exist
    And the leaf private key tempfile should exist

  # --- Negative fixtures: expired intermediate ---

  Scenario: expired intermediate CA chain variant
    Given a deterministic factory seeded with "expired-intermediate-test"
    When I generate a certificate chain for domain "test.example.com" with label "exp-int-check"
    And I get the expired intermediate variant of the certificate chain
    Then the expired intermediate certificate should have not_after in the past

  # --- Negative fixtures: unknown CA ---

  Scenario: unknown CA chain variant
    Given a deterministic factory seeded with "unknown-ca-test"
    When I generate a certificate chain for domain "test.example.com" with label "unknown-check"
    And I get the unknown CA variant of the certificate chain
    Then the chain root should differ from the original root
