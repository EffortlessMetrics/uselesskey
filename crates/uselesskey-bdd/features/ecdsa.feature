Feature: ECDSA fixtures
  As a test author
  I want to generate ECDSA key fixtures
  So that I can test ES256/ES384 cryptographic workflows without committing secrets

  # --- Determinism (ES256) ---

  Scenario: deterministic ES256 fixtures are stable
    Given a deterministic factory seeded with "0x0000000000000000000000000000000000000000000000000000000000000042"
    When I generate an ECDSA ES256 key for label "signer"
    And I generate an ECDSA ES256 key for label "signer" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: deterministic ECDSA derivation survives cache clear
    Given a deterministic factory seeded with "ecdsa-seed-alpha"
    When I generate an ECDSA ES256 key for label "first"
    And I clear the factory cache
    And I generate an ECDSA ES256 key for label "first" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: different labels produce different ECDSA keys
    Given a deterministic factory seeded with "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    When I generate an ECDSA ES256 key for label "alice"
    And I generate another ECDSA ES256 key for label "bob"
    Then the ECDSA keys should have different public keys

  Scenario: different seeds produce different ECDSA keys
    Given a deterministic factory seeded with "seed-one"
    When I generate an ECDSA ES256 key for label "service"
    And I switch to a deterministic factory seeded with "seed-two"
    And I generate another ECDSA ES256 key for label "service"
    Then the ECDSA keys should have different public keys

  # --- Random mode ---

  Scenario: random factory produces different ECDSA keys each time
    Given a random factory
    When I generate an ECDSA ES256 key for label "ephemeral"
    And I clear the factory cache
    And I generate an ECDSA ES256 key for label "ephemeral" again
    Then the ECDSA keys should have different public keys

  Scenario: random factory caches ECDSA within same session
    Given a random factory
    When I generate an ECDSA ES256 key for label "cached"
    And I generate an ECDSA ES256 key for label "cached" again
    Then the ECDSA PKCS8 PEM should be identical

  # --- ES384 variant ---

  Scenario: deterministic ES384 fixtures are stable
    Given a deterministic factory seeded with "es384-seed"
    When I generate an ECDSA ES384 key for label "p384-signer"
    And I generate an ECDSA ES384 key for label "p384-signer" again
    Then the ECDSA PKCS8 PEM should be identical

  Scenario: ES256 and ES384 produce different keys for same label
    Given a deterministic factory seeded with "curve-test"
    When I generate an ECDSA ES256 key for label "shared-label"
    And I generate another ECDSA ES384 key for label "shared-label"
    Then the ECDSA keys should have different public keys

  # --- Key formats ---

  Scenario: ECDSA PKCS8 DER private key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an ECDSA ES256 key for label "der-test"
    Then the ECDSA PKCS8 DER should be parseable

  Scenario: ECDSA SPKI PEM public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an ECDSA ES256 key for label "spki-test"
    Then the ECDSA SPKI PEM should be parseable

  Scenario: ECDSA SPKI DER public key is valid
    Given a deterministic factory seeded with "format-test"
    When I generate an ECDSA ES256 key for label "spki-der-test"
    Then the ECDSA SPKI DER should be parseable

  # --- Negative fixtures: mismatched keys ---

  Scenario: mismatched ECDSA public key is different
    Given a random factory
    When I generate an ECDSA ES256 key for label "signer"
    Then an ECDSA mismatched SPKI DER should parse and differ

  Scenario: mismatched ECDSA key is deterministic
    Given a deterministic factory seeded with "mismatch-test"
    When I generate an ECDSA ES256 key for label "victim"
    And I get the mismatched ECDSA public key
    And I get the mismatched ECDSA public key again
    Then the mismatched ECDSA keys should be identical

  # --- Negative fixtures: corruption ---

  Scenario: ECDSA corrupted PEM with BadHeader
    Given a deterministic factory seeded with "corrupt-test"
    When I generate an ECDSA ES256 key for label "corrupted"
    And I corrupt the ECDSA PKCS8 PEM with BadHeader
    Then the corrupted ECDSA PEM should contain "-----BEGIN CORRUPTED KEY-----"

  Scenario: ECDSA truncated DER fails to parse
    Given a deterministic factory seeded with "truncate-test"
    When I generate an ECDSA ES256 key for label "truncated"
    And I truncate the ECDSA PKCS8 DER to 10 bytes
    Then the truncated ECDSA DER should have length 10
    And the truncated ECDSA DER should fail to parse

  Scenario: deterministic ECDSA PEM corruption with variant is stable
    Given a deterministic factory seeded with "ecdsa-det-corrupt-pem"
    When I generate an ECDSA ES256 key for label "ecdsa-det-pem"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "v1"
    And I deterministically corrupt the ECDSA PKCS8 PEM with variant "v1" again
    Then the deterministic text artifacts should be identical
    And the deterministic ECDSA PEM artifact should fail to parse

  Scenario: deterministic ECDSA DER corruption with variant is stable
    Given a deterministic factory seeded with "ecdsa-det-corrupt-der"
    When I generate an ECDSA ES256 key for label "ecdsa-det-der"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "v1"
    And I deterministically corrupt the ECDSA PKCS8 DER with variant "v1" again
    Then the deterministic binary artifacts should be identical
    And the deterministic ECDSA DER artifact should fail to parse

  # --- JWK support (ES256) ---

  Scenario: ES256 public JWK has correct format
    Given a deterministic factory seeded with "jwk-test"
    When I generate an ECDSA ES256 key for label "jwt-signer"
    Then the ECDSA public JWK should have kty "EC"
    And the ECDSA public JWK should have crv "P-256"
    And the ECDSA public JWK should have alg "ES256"
    And the ECDSA public JWK should have use "sig"
    And the ECDSA public JWK should have a kid
    And the ECDSA public JWK should have x and y parameters

  Scenario: ES256 private JWK has correct format
    Given a deterministic factory seeded with "jwk-test"
    When I generate an ECDSA ES256 key for label "jwt-signer"
    Then the ECDSA private JWK should have d parameter

  Scenario: ECDSA JWKS has valid structure
    Given a deterministic factory seeded with "jwks-test"
    When I generate an ECDSA ES256 key for label "auth-service"
    Then the ECDSA JWKS should have a keys array
    And the ECDSA JWKS keys array should contain one key

  Scenario: ECDSA kid is deterministic
    Given a deterministic factory seeded with "kid-test"
    When I generate an ECDSA ES256 key for label "issuer"
    And I capture the ECDSA kid
    And I clear the factory cache
    And I generate an ECDSA ES256 key for label "issuer" again
    And I capture the ECDSA kid again
    Then the ECDSA kids should be identical

  # --- JWK support (ES384) ---

  Scenario: ES384 public JWK has correct format
    Given a deterministic factory seeded with "jwk-es384-test"
    When I generate an ECDSA ES384 key for label "jwt-signer-384"
    Then the ECDSA public JWK should have kty "EC"
    And the ECDSA public JWK should have crv "P-384"
    And the ECDSA public JWK should have alg "ES384"
    And the ECDSA public JWK should have use "sig"
