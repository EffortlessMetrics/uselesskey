Feature: Determinism edge cases
  As a test author
  I want to verify determinism holds under unusual combinations
  So that I can trust fixture stability across seed, label, and spec permutations

  # --- Same seed, same label, different key types produce different material ---

  Scenario: same seed and label across RSA and Ed25519 produce different kids
    Given a deterministic factory seeded with "det-edge-type-diff"
    When I generate an RSA key for label "shared" with spec RS256
    And I generate an ECDSA ES256 key for label "shared"
    And I generate an Ed25519 key for label "shared"
    And I generate an HMAC HS256 secret for label "shared"
    Then each key should have a unique kid

  # --- Same seed, different labels, same key type ---

  Scenario: same seed different labels produce different Ed25519 keys
    Given a deterministic factory seeded with "det-edge-label-ed"
    When I generate an Ed25519 key for label "label-alpha"
    And I generate another Ed25519 key for label "label-beta"
    Then the Ed25519 keys should have different public keys

  Scenario: same seed different labels produce different HMAC secrets
    Given a deterministic factory seeded with "det-edge-label-hmac"
    When I generate an HMAC HS256 secret for label "label-alpha"
    And I generate another HMAC HS256 secret for label "label-beta"
    Then the HMAC secrets should be different

  # --- Deterministic order independence: interleaved generation ---

  Scenario: interleaved key generation preserves determinism
    Given a deterministic factory seeded with "det-edge-interleave"
    When I generate an RSA key for label "rsa-first" with spec RS256
    And I generate an ECDSA ES256 key for label "ecdsa-first"
    And I generate an HMAC HS256 secret for label "hmac-first"
    And I generate an Ed25519 key for label "ed-first"
    And I clear the factory cache
    And I generate an Ed25519 key for label "ed-first" again
    Then the Ed25519 PKCS8 PEM should be identical

  Scenario: interleaved generation does not perturb token values
    Given a deterministic factory seeded with "det-edge-token-interleave"
    When I generate an API key token for label "token-first"
    And I generate an RSA key for label "interleave-rsa"
    And I generate an ECDSA ES256 key for label "interleave-ecdsa"
    And I clear the factory cache
    And I generate an API key token for label "token-first" again
    Then the token values should be identical

  # --- Same label with different variant strings ---

  Scenario: different variants produce different corrupted PEMs
    Given a deterministic factory seeded with "det-edge-variant-diff"
    When I generate an RSA key for label "variant-test"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "alpha"
    And I deterministically corrupt the RSA PKCS8 PEM with variant "beta" again
    Then the deterministic text artifacts should differ

  # --- X.509 determinism with same domain different labels ---

  Scenario: same domain different labels produce different X.509 certificates
    Given a deterministic factory seeded with "det-edge-x509-labels"
    When I generate an X.509 certificate for domain "shared.example.com" with label "cert-a"
    And I generate another X.509 certificate for domain "shared.example.com" with label "cert-b"
    Then the X.509 certificates should have different DER

  # --- Token determinism: same label across all token types ---

  Scenario: same label across API key and bearer produces different values
    Given a deterministic factory seeded with "det-edge-token-types-ab"
    When I generate an API key token for label "same-label"
    And I generate another bearer token for label "same-label"
    Then the token values should be different

  Scenario: same label across bearer and OAuth produces different values
    Given a deterministic factory seeded with "det-edge-token-types-bo"
    When I generate a bearer token for label "same-label"
    And I generate another OAuth access token for label "same-label"
    Then the token values should be different

  # --- Factory recreation determinism for X.509 ---

  Scenario: recreating factory with same seed yields identical X.509 certificate
    Given a deterministic factory seeded with "det-edge-x509-recreate"
    When I generate an X.509 certificate for domain "test.example.com" with label "stable-cert"
    And I switch to a deterministic factory seeded with "det-edge-x509-recreate"
    And I generate an X.509 certificate for domain "test.example.com" with label "stable-cert" again
    Then the X.509 certificate PEM should be identical
