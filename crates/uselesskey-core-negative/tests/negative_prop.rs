//! Property-based tests for `uselesskey-core-negative`.

use proptest::prelude::*;

use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

proptest! {
    /// `truncate_der` output is always a prefix of the input (or identity).
    #[test]
    fn truncate_der_is_prefix(
        der in prop::collection::vec(any::<u8>(), 1..256),
        len in 0usize..512,
    ) {
        let out = truncate_der(&der, len);
        let expected_len = len.min(der.len());
        prop_assert_eq!(out.len(), expected_len);
        prop_assert_eq!(&out[..], &der[..expected_len]);
    }

    /// `flip_byte` at a valid offset changes exactly one byte.
    #[test]
    fn flip_byte_changes_exactly_one(
        der in prop::collection::vec(any::<u8>(), 1..256),
        offset_pct in 0usize..100,
    ) {
        let offset = offset_pct % der.len();
        let out = flip_byte(&der, offset);
        prop_assert_eq!(out.len(), der.len());

        let diffs = out.iter().zip(der.iter()).filter(|(a, b)| a != b).count();
        prop_assert_eq!(diffs, 1);
        prop_assert_ne!(out[offset], der[offset]);
    }

    /// `flip_byte` is self-inverse (XOR 0x01 twice = identity).
    #[test]
    fn flip_byte_self_inverse(
        der in prop::collection::vec(any::<u8>(), 1..256),
        offset_pct in 0usize..100,
    ) {
        let offset = offset_pct % der.len();
        let twice = flip_byte(&flip_byte(&der, offset), offset);
        prop_assert_eq!(twice, der);
    }

    /// `flip_byte` at out-of-bounds offset returns a clone.
    #[test]
    fn flip_byte_oob_identity(
        der in prop::collection::vec(any::<u8>(), 1..128),
        extra in 0usize..100,
    ) {
        let offset = der.len() + extra;
        prop_assert_eq!(flip_byte(&der, offset), der);
    }

    /// Deterministic DER corruption is stable for the same variant.
    #[test]
    fn corrupt_der_deterministic_stable(
        der in prop::collection::vec(any::<u8>(), 2..128),
        variant in "[a-z]{1,16}",
    ) {
        let a = corrupt_der_deterministic(&der, &variant);
        let b = corrupt_der_deterministic(&der, &variant);
        prop_assert_eq!(a, b);
    }

    /// Deterministic DER corruption always produces output that is shorter
    /// or byte-different from the input (never identity).
    #[test]
    fn corrupt_der_deterministic_never_identity(
        der in prop::collection::vec(any::<u8>(), 2..128),
        variant in "[a-z]{1,16}",
    ) {
        let out = corrupt_der_deterministic(&der, &variant);
        prop_assert_ne!(out, der, "corruption must not be identity");
    }
}

// ---------------------------------------------------------------------------
// PEM helpers (re-exported surface)
// ---------------------------------------------------------------------------

fn pem_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9+/]{64,256}"
        .prop_map(|body| format!("-----BEGIN TEST KEY-----\n{body}\n-----END TEST KEY-----\n"))
}

proptest! {
    /// `corrupt_pem` with `BadHeader` always replaces the header.
    #[test]
    fn corrupt_pem_bad_header(pem in pem_strategy()) {
        let out = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert!(out.contains("BEGIN CORRUPTED KEY"));
    }

    /// `corrupt_pem` with `BadFooter` always replaces the footer.
    #[test]
    fn corrupt_pem_bad_footer(pem in pem_strategy()) {
        let out = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert!(out.contains("END CORRUPTED KEY"));
    }

    /// `corrupt_pem` with `BadBase64` injects invalid base64.
    #[test]
    fn corrupt_pem_bad_base64(pem in pem_strategy()) {
        let out = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    /// `corrupt_pem` with `ExtraBlankLine` adds exactly one line.
    #[test]
    fn corrupt_pem_extra_blank(pem in pem_strategy()) {
        let original_lines = pem.lines().count();
        let out = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        prop_assert_eq!(out.lines().count(), original_lines + 1);
    }

    /// Deterministic PEM corruption is stable.
    #[test]
    fn corrupt_pem_deterministic_stable(
        pem in pem_strategy(),
        variant in "[a-z]{1,12}",
    ) {
        let a = corrupt_pem_deterministic(&pem, &variant);
        let b = corrupt_pem_deterministic(&pem, &variant);
        prop_assert_eq!(a, b);
    }

    /// Deterministic PEM corruption never returns the original.
    #[test]
    fn corrupt_pem_deterministic_never_identity(
        pem in pem_strategy(),
        variant in "[a-z]{1,12}",
    ) {
        let out = corrupt_pem_deterministic(&pem, &variant);
        prop_assert_ne!(out, pem, "PEM corruption must not be identity");
    }
}
