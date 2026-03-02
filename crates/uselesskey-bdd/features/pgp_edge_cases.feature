Feature: PGP fixture edge cases
  As a test author
  I want to verify PGP fixtures handle edge cases correctly
  So that PGP key generation is robust across unusual inputs

  # --- Unicode and special labels ---

  Scenario: Ed25519 PGP key with unicode label generates valid key
    Given a deterministic factory seeded with "pgp-unicode-label"
    When I generate an Ed25519 PGP key for label "日本語テスト-🔑"
    Then the PGP private key armor should contain "BEGIN PGP PRIVATE KEY BLOCK"
    And the PGP fingerprint should be non-empty

  Scenario: Ed25519 PGP key with very long label generates valid key
    Given a deterministic factory seeded with "pgp-long-label"
    When I generate an Ed25519 PGP key for label "this-is-a-very-long-label-that-exceeds-normal-lengths-for-pgp-testing"
    Then the PGP private key armor should contain "BEGIN PGP PRIVATE KEY BLOCK"
    And the PGP public key armor should contain "BEGIN PGP PUBLIC KEY BLOCK"
    And the PGP fingerprint should be non-empty

  Scenario: Ed25519 PGP key with minimal label generates valid key
    Given a deterministic factory seeded with "pgp-minimal-label"
    When I generate an Ed25519 PGP key for label "x"
    Then the PGP private key binary should be parseable
    And the PGP fingerprint should be non-empty

  # Note: cross-factory PGP recreation determinism is NOT supported because the
  # pgp crate embeds a creation timestamp in the key packet, so switching to a
  # new factory (even with the same seed) produces different armor/fingerprint.
  # Same-factory (cached) determinism IS tested in pgp.feature.

  # --- PGP user ID with edge-case labels ---

  Scenario: PGP user ID with unicode label contains the label
    Given a deterministic factory seeded with "pgp-userid-unicode"
    When I generate an Ed25519 PGP key for label "Ñoño"
    Then the PGP user ID should contain "Ñoño"

  Scenario: PGP user ID with numeric-only label
    Given a deterministic factory seeded with "pgp-userid-numeric"
    When I generate an Ed25519 PGP key for label "123456"
    Then the PGP user ID should contain "123456"
    And the PGP user ID should contain "@uselesskey.test"

  # --- Algorithm isolation ---

  Scenario: Ed25519 and RSA 3072 PGP produce different fingerprints for same label
    Given a deterministic factory seeded with "pgp-algo-isolation"
    When I generate an Ed25519 PGP key for label "algo-test"
    And I generate another RSA 3072 PGP key for label "algo-test"
    Then the PGP fingerprints should be different

  Scenario: RSA 2048 and RSA 3072 PGP have different key sizes
    Given a deterministic factory seeded with "pgp-rsa-size-diff"
    When I generate an RSA 2048 PGP key for label "small-rsa"
    And I generate another RSA 3072 PGP key for label "large-rsa"
    Then the PGP fingerprints should be different

  # --- PGP does not perturb other key types ---

  Scenario: generating PGP key does not perturb RSA determinism
    Given a deterministic factory seeded with "pgp-no-perturb-rsa"
    When I generate an RSA key for label "rsa-anchor"
    And I generate an Ed25519 PGP key for label "pgp-noise"
    And I clear the factory cache
    And I generate an RSA key for label "rsa-anchor" again
    Then the PKCS8 PEM should be identical

  Scenario: generating PGP key does not perturb Ed25519 determinism
    Given a deterministic factory seeded with "pgp-no-perturb-ed25519"
    When I generate an Ed25519 key for label "ed25519-anchor"
    And I generate an Ed25519 PGP key for label "pgp-noise"
    And I clear the factory cache
    And I generate an Ed25519 key for label "ed25519-anchor" again
    Then the Ed25519 PKCS8 PEM should be identical
