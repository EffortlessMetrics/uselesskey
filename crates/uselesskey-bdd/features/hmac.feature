Feature: HMAC fixtures
  As a test author
  I want to generate HMAC secret fixtures
  So that I can test HS256/HS384/HS512 flows without committing secrets

  Scenario: deterministic HMAC secrets are stable
    Given a deterministic factory seeded with "hmac-seed"
    When I generate an HMAC HS256 secret for label "issuer"
    And I generate an HMAC HS256 secret for label "issuer" again
    Then the HMAC secrets should be identical

  Scenario: HMAC JWK has required fields
    Given a deterministic factory seeded with "hmac-jwk"
    When I generate an HMAC HS256 secret for label "jwt-signer"
    Then the HMAC JWK should have kty "oct"
    And the HMAC JWK should have alg "HS256"
    And the HMAC JWK should have use "sig"
    And the HMAC JWK should have a kid
    And the HMAC JWK should have k parameter

  Scenario: HMAC JWKS has valid structure
    Given a deterministic factory seeded with "hmac-jwks"
    When I generate an HMAC HS256 secret for label "issuer"
    Then the HMAC JWKS should have a keys array
    And the HMAC JWKS keys array should contain one key

  # --- HMAC variants ---

  Scenario: deterministic HS384 secrets are stable
    Given a deterministic factory seeded with "hs384-seed"
    When I generate an HMAC HS384 secret for label "hs384-issuer"
    And I generate an HMAC HS384 secret for label "hs384-issuer" again
    Then the HMAC secrets should be identical

  Scenario: deterministic HS512 secrets are stable
    Given a deterministic factory seeded with "hs512-seed"
    When I generate an HMAC HS512 secret for label "hs512-issuer"
    And I generate an HMAC HS512 secret for label "hs512-issuer" again
    Then the HMAC secrets should be identical

  Scenario: HMAC HS256 and HS384 produce different secrets for same label
    Given a deterministic factory seeded with "hmac-variant-test"
    When I generate an HMAC HS256 secret for label "shared-label"
    And I generate another HMAC HS384 secret for label "shared-label"
    Then the HMAC secrets should be different

  Scenario: HMAC HS384 and HS512 produce different secrets for same label
    Given a deterministic factory seeded with "hmac-variant-test-2"
    When I generate an HMAC HS384 secret for label "shared-label"
    And I generate another HMAC HS512 secret for label "shared-label"
    Then the HMAC secrets should be different

  # --- HMAC formats ---

  Scenario: HMAC secret bytes are accessible
    Given a deterministic factory seeded with "hmac-bytes-test"
    When I generate an HMAC HS256 secret for label "hmac-bytes"
    Then the HMAC secret bytes should have length 32

  Scenario: HMAC HS384 secret bytes have correct length
    Given a deterministic factory seeded with "hmac-hs384-bytes-test"
    When I generate an HMAC HS384 secret for label "hmac-hs384"
    Then the HMAC secret bytes should have length 48

  Scenario: HMAC HS512 secret bytes have correct length
    Given a deterministic factory seeded with "hmac-hs512-bytes-test"
    When I generate an HMAC HS512 secret for label "hmac-hs512"
    Then the HMAC secret bytes should have length 64

  # --- HMAC JWKS ---

  Scenario: HMAC HS384 JWK has required fields
    Given a deterministic factory seeded with "hmac-hs384-jwk"
    When I generate an HMAC HS384 secret for label "hs384-signer"
    Then the HMAC JWK should have kty "oct"
    And the HMAC JWK should have alg "HS384"
    And the HMAC JWK should have use "sig"
    And the HMAC JWK should have a kid
    And the HMAC JWK should have k parameter

  Scenario: HMAC HS512 JWK has required fields
    Given a deterministic factory seeded with "hmac-hs512-jwk"
    When I generate an HMAC HS512 secret for label "hs512-signer"
    Then the HMAC JWK should have kty "oct"
    And the HMAC JWK should have alg "HS512"
    And the HMAC JWK should have use "sig"
    And the HMAC JWK should have a kid
    And the HMAC JWK should have k parameter
