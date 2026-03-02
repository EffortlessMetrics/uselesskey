Feature: JWT signing and verification
  As a test author
  I want to sign and verify JWT fixtures
  So that I can test JWT-based authentication flows with uselesskey keys

  # --- Signing ---

  Scenario: sign JWT with RSA
    Given a deterministic factory seeded with "jwt-rsa-test"
    When I generate an RSA key for label "jwt-rsa"
    And I sign a JWT with the RSA key
    Then the JWT should be valid
    And the JWT header should have alg "RS256"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with ECDSA
    Given a deterministic factory seeded with "jwt-ecdsa-test"
    When I generate an ECDSA ES256 key for label "jwt-ecdsa"
    And I sign a JWT with the ECDSA key
    Then the JWT should be valid
    And the JWT header should have alg "ES256"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with Ed25519
    Given a deterministic factory seeded with "jwt-ed25519-test"
    When I generate an Ed25519 key for label "jwt-ed25519"
    And I sign a JWT with the Ed25519 key
    Then the JWT should be valid
    And the JWT header should have alg "EdDSA"
    And the JWT subject should be "jwt-subject"

  Scenario: sign JWT with HMAC
    Given a deterministic factory seeded with "jwt-hmac-test"
    When I generate an HMAC HS256 secret for label "jwt-hmac"
    And I sign a JWT with the HMAC key
    Then the JWT should be valid
    And the JWT header should have alg "HS256"
    And the JWT subject should be "jwt-subject"

  # --- Verification ---

  Scenario: verify JWT with RSA public key
    Given a deterministic factory seeded with "jwt-verify-rsa"
    When I generate an RSA key for label "jwt-verify-rsa"
    And I sign a JWT with the RSA key
    And I verify the JWT with the RSA public key
    Then the JWT should be valid

  Scenario: verify JWT with JWKS
    Given a deterministic factory seeded with "jwt-jwks"
    When I generate an RSA key for label "jwt-jwks"
    And I build a JWKS containing the RSA key with kid "jwt-key"
    And I sign a JWT with the RSA key
    And I verify the JWT with the JWKS
    Then the JWT should be valid

  Scenario: verify JWT fails with wrong algorithm
    Given a deterministic factory seeded with "jwt-wrong-alg"
    When I generate an RSA key for label "jwt-wrong-alg"
    And I sign a JWT with the RSA key
    And I attempt to verify the JWT with ES256 algorithm
    Then the JWT verification should fail

  Scenario: verify JWT fails with wrong key
    Given a deterministic factory seeded with "jwt-wrong-key"
    When I generate an RSA key for label "jwt-wrong"
    And I sign a JWT with the RSA key
    And I generate another RSA key for label "jwt-wrong-2"
    And I attempt to verify the JWT with the second RSA key
    Then the JWT verification should fail

  # --- Additional verification round-trips ---

  @jsonwebtoken
  Scenario: verify JWT with ECDSA public key
    Given a deterministic factory seeded with "jwt-verify-ecdsa"
    When I generate an ECDSA ES256 key for label "jwt-verify-ecdsa"
    And I sign a JWT with the ECDSA key
    And I verify the JWT with the ECDSA public key
    Then the JWT should be valid

  @jsonwebtoken
  Scenario: verify JWT with Ed25519 public key
    Given a deterministic factory seeded with "jwt-verify-ed25519"
    When I generate an Ed25519 key for label "jwt-verify-ed25519"
    And I sign a JWT with the Ed25519 key
    And I verify the JWT with the Ed25519 public key
    Then the JWT should be valid

  @jsonwebtoken
  Scenario: verify JWT with HMAC secret
    Given a deterministic factory seeded with "jwt-verify-hmac"
    When I generate an HMAC HS256 secret for label "jwt-verify-hmac"
    And I sign a JWT with the HMAC key
    And I verify the JWT with the HMAC secret
    Then the JWT should be valid

  # --- Deterministic JWT stability ---

  @jsonwebtoken
  Scenario: deterministic RSA JWT is stable across generations
    Given a deterministic factory seeded with "jwt-det-rsa"
    When I generate an RSA key for label "jwt-det-rsa"
    And I sign a JWT with the RSA key
    And I record the JWT token
    And I sign a JWT with the RSA key
    Then the JWT token should be identical to the recorded one

  # --- Cross-algorithm error paths ---

  @jsonwebtoken
  Scenario: verify JWT fails with HMAC key against RSA-signed token
    Given a deterministic factory seeded with "jwt-cross-alg"
    When I generate an RSA key for label "jwt-cross-rsa"
    And I sign a JWT with the RSA key
    And I attempt to verify the JWT with HS256 algorithm
    Then the JWT verification should fail
