Feature: Token fixture negative and isolation scenarios
  As a test author
  I want to verify token fixtures are isolated from other fixture types
  So that generating tokens never perturbs key material determinism

  # --- Token generation does not perturb key types ---

  Scenario: generating all token types does not perturb ECDSA determinism
    Given a deterministic factory seeded with "token-neg-ecdsa-isolation"
    When I generate an ECDSA ES256 key for label "ecdsa-anchor"
    And I generate an API key token for label "noise-api"
    And I generate a bearer token for label "noise-bearer"
    And I generate an OAuth access token for label "noise-oauth"
    And I clear the factory cache
    And I generate an ECDSA ES256 key for label "ecdsa-anchor" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: generating all token types does not perturb Ed25519 determinism
    Given a deterministic factory seeded with "token-neg-ed25519-isolation"
    When I generate an Ed25519 key for label "ed25519-anchor"
    And I generate an API key token for label "noise-api"
    And I generate a bearer token for label "noise-bearer"
    And I generate an OAuth access token for label "noise-oauth"
    And I clear the factory cache
    And I generate an Ed25519 key for label "ed25519-anchor" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: generating all token types does not perturb HMAC determinism
    Given a deterministic factory seeded with "token-neg-hmac-isolation"
    When I generate an HMAC HS256 secret for label "hmac-anchor"
    And I generate an API key token for label "noise-api"
    And I generate a bearer token for label "noise-bearer"
    And I generate an OAuth access token for label "noise-oauth"
    And I clear the factory cache
    And I generate an HMAC HS256 secret for label "hmac-anchor" again
    Then the HMAC secrets should be identical

  # --- Key generation does not perturb token determinism ---

  Scenario: generating keys does not perturb API key token determinism
    Given a deterministic factory seeded with "token-neg-api-stability"
    When I generate an API key token for label "stable-api"
    And I generate an RSA key for label "noise-rsa"
    And I generate an ECDSA ES256 key for label "noise-ecdsa"
    And I generate an Ed25519 key for label "noise-ed"
    And I clear the factory cache
    And I generate an API key token for label "stable-api" again
    Then the token values should be identical

  Scenario: generating keys does not perturb bearer token determinism
    Given a deterministic factory seeded with "token-neg-bearer-stability"
    When I generate a bearer token for label "stable-bearer"
    And I generate an RSA key for label "noise-rsa"
    And I generate an ECDSA ES256 key for label "noise-ecdsa"
    And I clear the factory cache
    And I generate a bearer token for label "stable-bearer" again
    Then the token values should be identical

  Scenario: generating keys does not perturb OAuth token determinism
    Given a deterministic factory seeded with "token-neg-oauth-stability"
    When I generate an OAuth access token for label "stable-oauth"
    And I generate an RSA key for label "noise-rsa"
    And I generate an HMAC HS256 secret for label "noise-hmac"
    And I clear the factory cache
    And I generate an OAuth access token for label "stable-oauth" again
    Then the token values should be identical

  # --- Token variant isolation ---

  Scenario: bearer token with variant produces different value than default
    Given a deterministic factory seeded with "token-bearer-variant-test"
    When I generate an API key token for label "service"
    And I generate an API key token for label "service" with variant "staging"
    Then the token values should be different

  Scenario: same variant string across different token types produces different values
    Given a deterministic factory seeded with "token-cross-variant"
    When I generate an API key token for label "same" with variant "v1"
    And I generate another bearer token for label "same"
    Then the token values should be different
