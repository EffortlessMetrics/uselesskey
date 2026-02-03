Feature: RSA fixtures
  Scenario: deterministic RSA fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an RSA key for label "issuer"
    And I generate an RSA key for label "issuer" again
    Then the PKCS8 PEM should be identical

  Scenario: mismatched public key is different
    Given a random factory
    When I generate an RSA key for label "issuer"
    Then a mismatched SPKI DER should parse and differ
