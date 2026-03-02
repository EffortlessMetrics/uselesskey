Feature: X.509 negative fixture edge cases
  As a test author
  I want to verify X.509 negative fixtures cover additional invalid certificate scenarios
  So that I can test comprehensive certificate validation error paths

  # --- Self-signed expired is deterministic ---

  Scenario: expired self-signed X.509 is deterministic across factory instances
    Given a deterministic factory seeded with "x509-neg-expired-det"
    When I generate an X.509 certificate for domain "test.example.com" with label "exp-det"
    And I get the expired variant of the X.509 certificate
    And I record the expired X.509 certificate DER
    And I switch to a deterministic factory seeded with "x509-neg-expired-det"
    And I generate an X.509 certificate for domain "test.example.com" with label "exp-det"
    And I get the expired variant of the X.509 certificate
    Then the expired X.509 certificate DER should match the recorded one

  # --- Not-yet-valid is deterministic ---

  Scenario: not-yet-valid X.509 is deterministic across factory instances
    Given a deterministic factory seeded with "x509-neg-future-det"
    When I generate an X.509 certificate for domain "test.example.com" with label "fut-det"
    And I get the not-yet-valid variant of the X.509 certificate
    And I record the not-yet-valid X.509 certificate DER
    And I switch to a deterministic factory seeded with "x509-neg-future-det"
    And I generate an X.509 certificate for domain "test.example.com" with label "fut-det"
    And I get the not-yet-valid variant of the X.509 certificate
    Then the not-yet-valid X.509 certificate DER should match the recorded one

  # --- Wrong key usage is deterministic ---

  Scenario: wrong-key-usage X.509 is deterministic across factory instances
    Given a deterministic factory seeded with "x509-neg-wku-det"
    When I generate an X.509 certificate for domain "test.example.com" with label "wku-det"
    And I get the wrong-key-usage variant of the X.509 certificate
    And I record the wrong-key-usage X.509 certificate DER
    And I switch to a deterministic factory seeded with "x509-neg-wku-det"
    And I generate an X.509 certificate for domain "test.example.com" with label "wku-det"
    And I get the wrong-key-usage variant of the X.509 certificate
    Then the wrong-key-usage X.509 certificate DER should match the recorded one

  # --- Multiple negative variants differ from each other ---

  Scenario: expired and not-yet-valid variants differ
    Given a deterministic factory seeded with "x509-neg-variants-differ"
    When I generate an X.509 certificate for domain "test.example.com" with label "variant-diff"
    And I get the expired variant of the X.509 certificate
    And I record the expired X.509 certificate DER
    And I get the not-yet-valid variant of the X.509 certificate
    Then the not-yet-valid X.509 certificate DER should differ from the expired one

  Scenario: expired and wrong-key-usage variants differ
    Given a deterministic factory seeded with "x509-neg-exp-vs-wku"
    When I generate an X.509 certificate for domain "test.example.com" with label "exp-wku-diff"
    And I get the expired variant of the X.509 certificate
    And I record the expired X.509 certificate DER
    And I get the wrong-key-usage variant of the X.509 certificate
    Then the wrong-key-usage X.509 certificate DER should differ from the expired one

  # --- Chain negative variants: unknown CA is deterministic ---

  Scenario: unknown CA chain variant is deterministic
    Given a deterministic factory seeded with "x509-neg-unknown-ca-det"
    When I generate a certificate chain for domain "test.example.com" with label "unknown-det"
    And I get the unknown CA variant of the certificate chain
    And I record the unknown CA root DER
    And I switch to a deterministic factory seeded with "x509-neg-unknown-ca-det"
    And I generate a certificate chain for domain "test.example.com" with label "unknown-det"
    And I get the unknown CA variant of the certificate chain
    Then the unknown CA root DER should match the recorded one

  # --- Chain negative variants: revoked is deterministic ---

  Scenario: revoked leaf chain variant is deterministic
    Given a deterministic factory seeded with "x509-neg-revoked-det"
    When I generate a certificate chain for domain "test.example.com" with label "revoked-det"
    And I get the revoked leaf variant of the certificate chain
    And I record the revoked leaf DER
    And I switch to a deterministic factory seeded with "x509-neg-revoked-det"
    And I generate a certificate chain for domain "test.example.com" with label "revoked-det"
    And I get the revoked leaf variant of the certificate chain
    Then the revoked leaf DER should match the recorded one

  # --- Chain negative variants: hostname mismatch is deterministic ---

  Scenario: hostname mismatch chain variant is deterministic
    Given a deterministic factory seeded with "x509-neg-hostname-det"
    When I generate a certificate chain for domain "test.example.com" with label "hostname-det"
    And I get the hostname mismatch variant with "wrong.example.com"
    And I record the hostname mismatch leaf DER
    And I switch to a deterministic factory seeded with "x509-neg-hostname-det"
    And I generate a certificate chain for domain "test.example.com" with label "hostname-det"
    And I get the hostname mismatch variant with "wrong.example.com"
    Then the hostname mismatch leaf DER should match the recorded one
