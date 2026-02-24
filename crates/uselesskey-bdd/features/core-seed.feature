Feature: Core seed parsing primitives
  As a test author
  I want seed parsing and debug redaction isolated in a microcrate
  So deterministic fixture seeds are easy to validate and safe to log

  Scenario: hex seed with prefix parses to expected bytes
    Given a core-seed raw value "0x0000000000000000000000000000000000000000000000000000000000000001"
    Then the core-seed parse should succeed
    And the core-seed last byte should be 1

  Scenario: invalid 64-char hex reports a parse error
    Given a core-seed raw value "gg00000000000000000000000000000000000000000000000000000000000000"
    Then the core-seed parse should fail
    And the core-seed error should contain "invalid hex char"

  Scenario: debug output redacts seed material
    Given a core-seed raw value "seed-redaction-check"
    Then the core-seed parse should succeed
    And the core-seed debug output should be redacted
