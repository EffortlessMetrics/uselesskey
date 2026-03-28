# uselesskey-symmetric

Deterministic symmetric-key and AEAD vector fixtures for test code.

- symmetric fixture (`key + nonce + alg + optional kid`)
- AEAD vector fixture (`plaintext + aad + ciphertext + tag + nonce`)

Built on top of `uselesskey-core` deterministic derivation and cache identities.
