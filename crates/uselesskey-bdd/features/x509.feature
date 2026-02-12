Feature: X.509 certificate fixtures
  As a test author
  I want to generate X.509 certificate fixtures
  So that I can test TLS and certificate validation without committing secrets

  # --- Determinism ---

  Scenario: deterministic X.509 certificates are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an X.509 certificate for domain "test.example.com" with label "server"
    And I generate an X.509 certificate for domain "test.example.com" with label "server" again
    Then the X.509 certificate PEM should be identical

  Scenario: deterministic X.509 derivation survives cache clear
    Given a deterministic factory seeded with "x509-seed-alpha"
    When I generate an X.509 certificate for domain "api.example.com" with label "first"
    And I clear the factory cache
    And I generate an X.509 certificate for domain "api.example.com" with label "first" again
    Then the X.509 certificate PEM should be identical

  Scenario: different labels produce different X.509 certificates
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an X.509 certificate for domain "test.example.com" with label "server-a"
    And I generate another X.509 certificate for domain "test.example.com" with label "server-b"
    Then the X.509 certificates should have different DER

  Scenario: different seeds produce different X.509 certificates
    Given a deterministic factory seeded with "seed-one"
    When I generate an X.509 certificate for domain "test.example.com" with label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another X.509 certificate for domain "test.example.com" with label "service"
    Then the X.509 certificates should have different DER

  # --- Random mode ---

  Scenario: random factory produces different X.509 certificates each time
    Given a random factory
    When I generate an X.509 certificate for domain "test.example.com" with label "ephemeral"
    And I clear the factory cache
    And I generate an X.509 certificate for domain "test.example.com" with label "ephemeral" again
    Then the X.509 certificates should have different DER

  Scenario: random factory caches X.509 within same session
    Given a random factory
    When I generate an X.509 certificate for domain "test.example.com" with label "cached"
    And I generate an X.509 certificate for domain "test.example.com" with label "cached" again
    Then the X.509 certificate PEM should be identical

  # --- Certificate formats ---

  Scenario: X.509 certificate PEM is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "pem-test"
    Then the X.509 certificate PEM should contain "-----BEGIN CERTIFICATE-----"
    And the X.509 certificate PEM should be parseable

  Scenario: X.509 certificate DER is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "der-test"
    Then the X.509 certificate DER should be parseable

  Scenario: X.509 private key PEM is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "key-test"
    Then the X.509 private key PEM should contain "-----BEGIN PRIVATE KEY-----"

  Scenario: X.509 identity PEM contains both certificate and key
    Given a deterministic factory seeded with "format-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "chain-test"
    Then the X.509 identity PEM should contain "-----BEGIN CERTIFICATE-----"
    And the X.509 identity PEM should contain "-----BEGIN PRIVATE KEY-----"

  # --- Certificate metadata ---

  Scenario: X.509 certificate has correct common name
    Given a deterministic factory seeded with "cn-test"
    When I generate an X.509 certificate for domain "myservice.example.com" with label "cn-check"
    Then the X.509 certificate should have common name "myservice.example.com"

  # --- Negative fixtures: expired ---

  Scenario: expired X.509 certificate is different from valid
    Given a deterministic factory seeded with "expired-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "expired-check"
    And I get the expired variant of the X.509 certificate
    Then the X.509 certificates should have different DER

  Scenario: expired X.509 certificate is parseable but invalid
    Given a deterministic factory seeded with "expired-parse-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "expired-parse"
    And I get the expired variant of the X.509 certificate
    Then the expired X.509 certificate should be parseable
    And the expired X.509 certificate should have not_after in the past

  # --- Negative fixtures: not yet valid ---

  Scenario: not-yet-valid X.509 certificate is different from valid
    Given a deterministic factory seeded with "not-yet-valid-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "future-check"
    And I get the not-yet-valid variant of the X.509 certificate
    Then the X.509 certificates should have different DER

  Scenario: not-yet-valid X.509 certificate is parseable but not yet active
    Given a deterministic factory seeded with "not-yet-valid-parse-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "future-parse"
    And I get the not-yet-valid variant of the X.509 certificate
    Then the not-yet-valid X.509 certificate should be parseable
    And the not-yet-valid X.509 certificate should have not_before in the future

  # --- Negative fixtures: corruption ---

  Scenario: X.509 corrupted PEM with BadHeader
    Given a deterministic factory seeded with "corrupt-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "corrupted"
    And I corrupt the X.509 certificate PEM with BadHeader
    Then the corrupted X.509 PEM should contain "-----BEGIN CORRUPTED KEY-----"

  Scenario: X.509 truncated DER fails to parse
    Given a deterministic factory seeded with "truncate-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "truncated"
    And I truncate the X.509 certificate DER to 10 bytes
    Then the truncated X.509 DER should have length 10
    And the truncated X.509 DER should fail to parse

  # --- Tempfile outputs ---

  Scenario: X.509 certificate writes to tempfile
    Given a deterministic factory seeded with "tempfile-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "temp-cert"
    And I write the X.509 certificate PEM to a tempfile
    Then the X.509 tempfile path should end with ".crt.pem"
    And reading the X.509 tempfile should match the certificate PEM

  Scenario: X.509 private key writes to tempfile
    Given a deterministic factory seeded with "tempfile-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "temp-key"
    And I write the X.509 private key PEM to a tempfile
    Then the X.509 key tempfile path should end with ".key.pem"
    And reading the X.509 key tempfile should match the private key PEM

  Scenario: X.509 identity PEM writes to tempfile
    Given a deterministic factory seeded with "tempfile-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "temp-chain"
    And I write the X.509 identity PEM to a tempfile
    Then the X.509 chain tempfile path should end with ".identity.pem"

  # --- Certificate Chains ---

  Scenario: generate X.509 certificate chain
    Given a deterministic factory seeded with "chain-test"
    When I generate a certificate chain for domain "test.example.com" with label "test-chain"
    Then the certificate chain should contain a leaf certificate
    And the certificate chain should contain an intermediate certificate
    And the certificate chain should contain a root certificate

  Scenario: certificate chain is deterministic
    Given a deterministic factory seeded with "chain-deterministic"
    When I generate a certificate chain for domain "api.example.com" with label "chain-1"
    And I generate a certificate chain for domain "api.example.com" with label "chain-1" again
    Then the certificate chains should have identical DER

  # --- CRL and Revoked Certs ---

  Scenario: X.509 certificate chain with revoked leaf
    Given a deterministic factory seeded with "crl-test"
    When I generate a certificate chain for domain "test.example.com" with label "revoked-chain"
    And I get the revoked leaf variant of the certificate chain
    Then the revoked leaf certificate should be parseable
    And the revoked leaf certificate should have a CRL distribution point

  Scenario: revoked leaf certificate is different from valid
    Given a deterministic factory seeded with "revoked-diff-test"
    When I generate a certificate chain for domain "test.example.com" with label "revoked-check"
    And I get the revoked leaf variant of the certificate chain
    Then the revoked leaf certificate should differ from the valid leaf certificate

  # --- Hostname Mismatch ---

  Scenario: X.509 certificate chain with hostname mismatch
    Given a deterministic factory seeded with "hostname-mismatch-test"
    When I generate a certificate chain for domain "test.example.com" with label "mismatch-chain"
    And I get the hostname mismatch variant with "wrong.example.com"
    Then the leaf certificate should have common name "wrong.example.com"
    And the leaf certificate should not contain SAN "test.example.com"

  Scenario: hostname mismatch chain is different from valid
    Given a deterministic factory seeded with "hostname-diff-test"
    When I generate a certificate chain for domain "test.example.com" with label "hostname-check"
    And I get the hostname mismatch variant with "wrong.example.com"
    Then the hostname mismatch leaf certificate should differ from the valid leaf certificate

  # --- Chain Negative Variants ---

  Scenario: X.509 certificate chain with expired leaf
    Given a deterministic factory seeded with "expired-leaf-test"
    When I generate a certificate chain for domain "test.example.com" with label "expired-leaf-chain"
    And I get the expired leaf variant of the certificate chain
    Then the expired leaf certificate should have not_after in the past
    And the intermediate certificate should be valid

  Scenario: X.509 certificate chain with expired intermediate
    Given a deterministic factory seeded with "expired-int-test"
    When I generate a certificate chain for domain "test.example.com" with label "expired-int-chain"
    And I get the expired intermediate variant of the certificate chain
    Then the expired intermediate certificate should have not_after in the past
    And the leaf certificate should be valid

  # --- SAN Validation ---

  Scenario: X.509 certificate with multiple SANs
    Given a deterministic factory seeded with "san-test"
    When I generate an X.509 certificate for domain "test.example.com" with label "multi-san"
    And I add SAN "localhost" to the X.509 certificate
    And I add SAN "127.0.0.1" to the X.509 certificate
    And I add SAN "*.example.com" to the X.509 certificate
    Then the X.509 certificate should contain SAN "test.example.com"
    And the X.509 certificate should contain SAN "localhost"
    And the X.509 certificate should contain SAN "127.0.0.1"
    And the X.509 certificate should contain SAN "*.example.com"

  Scenario: X.509 certificate chain SANs are in leaf only
    Given a deterministic factory seeded with "chain-san-test"
    When I generate a certificate chain for domain "test.example.com" with label "san-chain"
    And I add SAN "localhost" to the certificate chain
    Then the leaf certificate should contain SAN "test.example.com"
    And the leaf certificate should contain SAN "localhost"
    And the intermediate certificate should not contain SAN "localhost"
    And the root certificate should not contain SAN "localhost"
