//! Negative fixture validation tests for HMAC secrets.
//!
//! HMAC is symmetric and has no PEM/DER key material to corrupt.
//! These tests verify that different secrets fail cross-validation,
//! truncated secrets produce invalid MACs, and secret generation
//! with different specs/labels produces distinct material.

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

// =========================================================================
// Different labels produce different secrets (cross-validation fails)
// =========================================================================

#[test]
fn different_labels_produce_different_secrets() {
    let fx = fx();
    let s1 = fx.hmac("secret-a", HmacSpec::hs256());
    let s2 = fx.hmac("secret-b", HmacSpec::hs256());

    assert_ne!(
        s1.secret_bytes(),
        s2.secret_bytes(),
        "Different labels should produce different secrets"
    );
}

#[test]
fn different_specs_produce_different_secrets_for_same_label() {
    let fx = fx();
    let s256 = fx.hmac("same-label", HmacSpec::hs256());
    let s384 = fx.hmac("same-label", HmacSpec::hs384());
    let s512 = fx.hmac("same-label", HmacSpec::hs512());

    assert_ne!(s256.secret_bytes(), s384.secret_bytes());
    assert_ne!(s256.secret_bytes(), s512.secret_bytes());
    assert_ne!(s384.secret_bytes(), s512.secret_bytes());
}

// =========================================================================
// Secret lengths match spec requirements
// =========================================================================

#[test]
fn hs256_secret_is_32_bytes() {
    let fx = fx();
    let s = fx.hmac("len-256", HmacSpec::hs256());
    assert_eq!(s.secret_bytes().len(), 32);
}

#[test]
fn hs384_secret_is_48_bytes() {
    let fx = fx();
    let s = fx.hmac("len-384", HmacSpec::hs384());
    assert_eq!(s.secret_bytes().len(), 48);
}

#[test]
fn hs512_secret_is_64_bytes() {
    let fx = fx();
    let s = fx.hmac("len-512", HmacSpec::hs512());
    assert_eq!(s.secret_bytes().len(), 64);
}

// =========================================================================
// Truncated HMAC secret produces wrong MAC (manual HMAC-SHA256)
// =========================================================================

#[test]
fn truncated_secret_produces_different_mac() {
    use hmac_sha256::Hmac;

    let fx = fx();
    let s = fx.hmac("trunc-hmac", HmacSpec::hs256());
    let full_secret = s.secret_bytes();
    let message = b"test message for HMAC verification";

    let good_mac = Hmac::mac(message, full_secret);

    // A truncated secret should produce a different MAC
    let truncated = &full_secret[..16];
    let bad_mac = Hmac::mac(message, truncated);

    assert_ne!(
        good_mac, bad_mac,
        "Truncated secret should produce a different MAC"
    );
}

// =========================================================================
// HMAC secrets are deterministic
// =========================================================================

#[test]
fn hmac_secrets_are_deterministic_across_factories() {
    let seed = Seed::from_env_value("hmac-neg-det").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    for spec_fn in [HmacSpec::hs256, HmacSpec::hs384, HmacSpec::hs512] {
        let s1 = fx1.hmac("det-test", spec_fn());
        let s2 = fx2.hmac("det-test", spec_fn());
        assert_eq!(
            s1.secret_bytes(),
            s2.secret_bytes(),
            "HMAC secrets should be deterministic"
        );
    }
}

// =========================================================================
// Secrets are non-zero (not degenerate)
// =========================================================================

#[test]
fn secrets_are_non_zero() {
    let fx = fx();
    for spec_fn in [HmacSpec::hs256, HmacSpec::hs384, HmacSpec::hs512] {
        let s = fx.hmac("nonzero", spec_fn());
        let all_zero = s.secret_bytes().iter().all(|&b| b == 0);
        assert!(!all_zero, "Secret should not be all zeros");
    }
}

mod hmac_sha256 {
    //! Minimal HMAC-SHA256 implementation for testing.

    use std::num::Wrapping;

    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    pub struct Hmac;

    impl Hmac {
        pub fn mac(message: &[u8], key: &[u8]) -> [u8; HASH_SIZE] {
            let mut padded_key = [0u8; BLOCK_SIZE];
            if key.len() > BLOCK_SIZE {
                let hashed = sha256(key);
                padded_key[..HASH_SIZE].copy_from_slice(&hashed);
            } else {
                padded_key[..key.len()].copy_from_slice(key);
            }

            let mut i_key_pad = [0x36u8; BLOCK_SIZE];
            let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                i_key_pad[i] ^= padded_key[i];
                o_key_pad[i] ^= padded_key[i];
            }

            let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
            inner.extend_from_slice(&i_key_pad);
            inner.extend_from_slice(message);
            let inner_hash = sha256(&inner);

            let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
            outer.extend_from_slice(&o_key_pad);
            outer.extend_from_slice(&inner_hash);
            sha256(&outer)
        }
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h: [Wrapping<u32>; 8] = [
            Wrapping(0x6a09e667),
            Wrapping(0xbb67ae85),
            Wrapping(0x3c6ef372),
            Wrapping(0xa54ff53a),
            Wrapping(0x510e527f),
            Wrapping(0x9b05688c),
            Wrapping(0x1f83d9ab),
            Wrapping(0x5be0cd19),
        ];

        let k: [Wrapping<u32>; 64] = [
            Wrapping(0x428a2f98),
            Wrapping(0x71374491),
            Wrapping(0xb5c0fbcf),
            Wrapping(0xe9b5dba5),
            Wrapping(0x3956c25b),
            Wrapping(0x59f111f1),
            Wrapping(0x923f82a4),
            Wrapping(0xab1c5ed5),
            Wrapping(0xd807aa98),
            Wrapping(0x12835b01),
            Wrapping(0x243185be),
            Wrapping(0x550c7dc3),
            Wrapping(0x72be5d74),
            Wrapping(0x80deb1fe),
            Wrapping(0x9bdc06a7),
            Wrapping(0xc19bf174),
            Wrapping(0xe49b69c1),
            Wrapping(0xefbe4786),
            Wrapping(0x0fc19dc6),
            Wrapping(0x240ca1cc),
            Wrapping(0x2de92c6f),
            Wrapping(0x4a7484aa),
            Wrapping(0x5cb0a9dc),
            Wrapping(0x76f988da),
            Wrapping(0x983e5152),
            Wrapping(0xa831c66d),
            Wrapping(0xb00327c8),
            Wrapping(0xbf597fc7),
            Wrapping(0xc6e00bf3),
            Wrapping(0xd5a79147),
            Wrapping(0x06ca6351),
            Wrapping(0x14292967),
            Wrapping(0x27b70a85),
            Wrapping(0x2e1b2138),
            Wrapping(0x4d2c6dfc),
            Wrapping(0x53380d13),
            Wrapping(0x650a7354),
            Wrapping(0x766a0abb),
            Wrapping(0x81c2c92e),
            Wrapping(0x92722c85),
            Wrapping(0xa2bfe8a1),
            Wrapping(0xa81a664b),
            Wrapping(0xc24b8b70),
            Wrapping(0xc76c51a3),
            Wrapping(0xd192e819),
            Wrapping(0xd6990624),
            Wrapping(0xf40e3585),
            Wrapping(0x106aa070),
            Wrapping(0x19a4c116),
            Wrapping(0x1e376c08),
            Wrapping(0x2748774c),
            Wrapping(0x34b0bcb5),
            Wrapping(0x391c0cb3),
            Wrapping(0x4ed8aa4a),
            Wrapping(0x5b9cca4f),
            Wrapping(0x682e6ff3),
            Wrapping(0x748f82ee),
            Wrapping(0x78a5636f),
            Wrapping(0x84c87814),
            Wrapping(0x8cc70208),
            Wrapping(0x90befffa),
            Wrapping(0xa4506ceb),
            Wrapping(0xbef9a3f7),
            Wrapping(0xc67178f2),
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut padded = data.to_vec();
        padded.push(0x80);
        while (padded.len() % 64) != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in padded.chunks_exact(64) {
            let mut w = [Wrapping(0u32); 64];
            for i in 0..16 {
                w[i] = Wrapping(u32::from_be_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]));
            }
            for i in 16..64 {
                let s0 = rotr(w[i - 15].0, 7) ^ rotr(w[i - 15].0, 18) ^ Wrapping(w[i - 15].0 >> 3);
                let s1 = rotr(w[i - 2].0, 17) ^ rotr(w[i - 2].0, 19) ^ Wrapping(w[i - 2].0 >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

            for i in 0..64 {
                let s1 = rotr(e.0, 6) ^ rotr(e.0, 11) ^ rotr(e.0, 25);
                let ch = (e & f) ^ (!e & g);
                let temp1 = hh + s1 + ch + k[i] + w[i];
                let s0 = rotr(a.0, 2) ^ rotr(a.0, 13) ^ rotr(a.0, 22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0 + maj;

                hh = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        let mut result = [0u8; 32];
        for i in 0..8 {
            result[4 * i..4 * i + 4].copy_from_slice(&h[i].0.to_be_bytes());
        }
        result
    }

    fn rotr(x: u32, n: u32) -> Wrapping<u32> {
        Wrapping(x.rotate_right(n))
    }
}
