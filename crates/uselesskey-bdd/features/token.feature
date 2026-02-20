Feature: Token fixtures
  As a test author
  I want to generate token fixtures
  So that I can test authentication workflows without committing secrets

  # --- Determinism ---

  Scenario: deterministic API key fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an API key token for label "service"
    And I generate an API key token for label "service" again
    Then the token values should be identical

  Scenario: deterministic token derivation survives cache clear
    Given a deterministic factory seeded with "token-seed-alpha"
    When I generate an API key token for label "first"
    And I clear the factory cache
    And I generate an API key token for label "first" again
    Then the token values should be identical

  Scenario: different labels produce different API keys
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an API key token for label "alice"
    And I generate another API key token for label "bob"
    Then the token values should be different

  Scenario: different seeds produce different API keys
    Given a deterministic factory seeded with "seed-one"
    When I generate an API key token for label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another API key token for label "service"
    Then the token values should be different

  # --- Random mode ---

  Scenario: random factory produces different tokens each time
    Given a random factory
    When I generate an API key token for label "ephemeral"
    And I clear the factory cache
    And I generate an API key token for label "ephemeral" again
    Then the token values should be different

  Scenario: random factory caches tokens within same session
    Given a random factory
    When I generate an API key token for label "cached"
    And I generate an API key token for label "cached" again
    Then the token values should be identical

  # --- Token types: API key ---

  Scenario: API key has correct format
    Given a deterministic factory seeded with "apikey-format"
    When I generate an API key token for label "test-service"
    Then the token value should start with "uk_test_"
    And the token value should have length 40

  Scenario: API key authorization header is correct
    Given a deterministic factory seeded with "apikey-auth"
    When I generate an API key token for label "api-client"
    Then the authorization header should start with "ApiKey "

  # --- Token types: Bearer ---

  Scenario: deterministic bearer token fixtures are stable
    Given a deterministic factory seeded with "bearer-seed"
    When I generate a bearer token for label "user"
    And I generate a bearer token for label "user" again
    Then the token values should be identical

  Scenario: bearer token has correct format
    Given a deterministic factory seeded with "bearer-format"
    When I generate a bearer token for label "test-user"
    Then the token value should be valid base64url
    And the token value should have length 43

  Scenario: bearer token authorization header is correct
    Given a deterministic factory seeded with "bearer-auth"
    When I generate a bearer token for label "bearer-client"
    Then the authorization header should start with "Bearer "

  # --- Token types: OAuth access token ---

  Scenario: deterministic OAuth access token fixtures are stable
    Given a deterministic factory seeded with "oauth-seed"
    When I generate an OAuth access token for label "app"
    And I generate an OAuth access token for label "app" again
    Then the token values should be identical

  Scenario: OAuth access token has JWT format
    Given a deterministic factory seeded with "oauth-format"
    When I generate an OAuth access token for label "oauth-client"
    Then the token value should have three dot-separated segments
    And the token value header should decode to valid JSON

  Scenario: OAuth access token authorization header is correct
    Given a deterministic factory seeded with "oauth-auth"
    When I generate an OAuth access token for label "oauth-client"
    Then the authorization header should start with "Bearer "

  Scenario: OAuth access token payload has required claims
    Given a deterministic factory seeded with "oauth-claims"
    When I generate an OAuth access token for label "test-app"
    Then the OAuth payload should contain issuer "uselesskey"
    And the OAuth payload should contain subject "test-app"
    And the OAuth payload should contain audience "tests"
    And the OAuth payload should contain scope "fixture.read"

  # --- Token spec variants ---

  Scenario: different token specs produce different values for same label
    Given a deterministic factory seeded with "token-variant-test"
    When I generate an API key token for label "shared-label"
    And I generate a bearer token for label "shared-label"
    Then the token values should be different

  Scenario: bearer and OAuth token produce different values for same label
    Given a deterministic factory seeded with "bearer-oauth-variant"
    When I generate a bearer token for label "shared-label"
    And I generate an OAuth access token for label "shared-label"
    Then the token values should be different

  # --- Token with variant ---

  Scenario: token with variant produces different value
    Given a deterministic factory seeded with "variant-test"
    When I generate an API key token for label "service"
    And I generate an API key token for label "service" with variant "alt"
    Then the token values should be different

  Scenario: token with same variant is deterministic
    Given a deterministic factory seeded with "variant-det-test"
    When I generate an API key token for label "service" with variant "v1"
    And I generate an API key token for label "service" with variant "v1" again
    Then the token values should be identical
