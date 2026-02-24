# uselesskey-core-keypair

Compatibility facade for PKCS#8/SPKI key-material helpers used by `uselesskey`
fixture crates.

The concrete implementation moved to
[`uselesskey-core-keypair-material`](../uselesskey-core-keypair-material). This crate now
re-exports the public API to keep the historical crate path stable while isolating
responsibility into a focused microcrate.
