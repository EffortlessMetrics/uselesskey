Feature: Token fixture edge cases
  As a test author
  I want to verify token fixtures handle edge cases correctly
  So that tokens are robust across unusual inputs and usage patterns

  # --- Empty and special label edge cases ---

  Scenario: API key with minimal label generates valid token
    Given a deterministic factory seeded with "token-minimal-label"
    When I generate an API key token for label "x"
    Then the token value should start with "uk_test_"
    And the token value should have length 40

  Scenario: bearer token with minimal label generates valid token
    Given a deterministic factory seeded with "bearer-minimal-label"
    When I generate a bearer token for label "x"
    Then the token value should be valid base64url
    And the token value should have length 43

  Scenario: OAuth token with minimal label generates valid token
    Given a deterministic factory seeded with "oauth-minimal-label"
    When I generate an OAuth access token for label "x"
    Then the token value should have three dot-separated segments
    And the token value header should decode to valid JSON

  Scenario: API key with unicode label generates valid token
    Given a deterministic factory seeded with "token-unicode-label"
    When I generate an API key token for label "日本語テスト-🔑"
    Then the token value should start with "uk_test_"
    And the token value should have length 40

  Scenario: bearer token with very long label generates valid token
    Given a deterministic factory seeded with "token-long-label"
    When I generate a bearer token for label "this-is-a-very-long-label-that-exceeds-normal-lengths-for-testing"
    Then the token value should be valid base64url
    And the token value should have length 43

  # --- API key format validation ---

  Scenario: API key contains only printable ASCII
    Given a deterministic factory seeded with "apikey-printable-ascii"
    When I generate an API key token for label "ascii-check"
    Then the token value should contain only printable ASCII

  Scenario: API key prefix is consistent across labels
    Given a deterministic factory seeded with "apikey-prefix-consistency"
    When I generate an API key token for label "first-service"
    Then the token value should start with "uk_test_"
    When I generate an API key token for label "second-service"
    Then the token value should start with "uk_test_"

  # --- OAuth payload edge cases ---

  Scenario: OAuth access token payload contains exp claim
    Given a deterministic factory seeded with "oauth-exp-check"
    When I generate an OAuth access token for label "exp-test"
    Then the OAuth payload should contain an exp claim

  Scenario: OAuth access token payload contains scope claim
    Given a deterministic factory seeded with "oauth-scope-check"
    When I generate an OAuth access token for label "scope-test"
    Then the OAuth payload should contain a scope claim

  # --- Deterministic recreation across factory instances ---

  Scenario: recreating factory with same seed yields identical API key
    Given a deterministic factory seeded with "token-recreation-apikey"
    When I generate an API key token for label "stable-api"
    And I switch to a deterministic factory seeded with "token-recreation-apikey"
    And I generate an API key token for label "stable-api" again
    Then the token values should be identical

  Scenario: recreating factory with same seed yields identical bearer token
    Given a deterministic factory seeded with "token-recreation-bearer"
    When I generate a bearer token for label "stable-bearer"
    And I switch to a deterministic factory seeded with "token-recreation-bearer"
    And I generate a bearer token for label "stable-bearer" again
    Then the token values should be identical

  Scenario: recreating factory with same seed yields identical OAuth token
    Given a deterministic factory seeded with "token-recreation-oauth"
    When I generate an OAuth access token for label "stable-oauth"
    And I switch to a deterministic factory seeded with "token-recreation-oauth"
    And I generate an OAuth access token for label "stable-oauth" again
    Then the token values should be identical

  # --- Different seeds produce different tokens for bearer and OAuth ---

  Scenario: different seeds produce different bearer tokens
    Given a deterministic factory seeded with "bearer-seed-one"
    When I generate a bearer token for label "service"
    And I switch to a deterministic factory seeded with "bearer-seed-two"
    And I generate another bearer token for label "service"
    Then the token values should be different

  Scenario: different seeds produce different OAuth tokens
    Given a deterministic factory seeded with "oauth-seed-one"
    When I generate an OAuth access token for label "service"
    And I switch to a deterministic factory seeded with "oauth-seed-two"
    And I generate another OAuth access token for label "service"
    Then the token values should be different
