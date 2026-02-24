use proptest::prelude::*;

use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, X509Spec};

fn make_ascii_label(seed: &[u8]) -> String {
    let mut out = String::new();
    for b in seed.iter().copied() {
        out.push(char::from((b % 26) + b'a'));
    }
    if out.is_empty() {
        "integration".to_string()
    } else {
        out
    }
}

proptest! {
    #[test]
    fn x509_negative_application_is_deterministic(
        label in "[a-z]{1,16}",
        validity in 1u32..4000
    ) {
        let base = X509Spec::self_signed(&label).with_validity_days(validity);
        let first = X509Negative::NotYetValid.apply_to_spec(&base);
        let second = X509Negative::NotYetValid.apply_to_spec(&base);

        assert_eq!(first, second);
    }

    #[test]
    fn chain_negative_hostname_mismatch_is_deterministic(
        leaf in "[a-z]{1,16}",
        wrong in "[a-z]{1,16}",
    ) {
        let base = ChainSpec::new(leaf);
        let variant = ChainNegative::HostnameMismatch {
            wrong_hostname: wrong.clone(),
        };
        let first = variant.apply_to_spec(&base);
        let second = variant.apply_to_spec(&base);

        assert_eq!(first, second);
    }

    #[test]
    fn variant_name_for_x509_is_nonempty(bytes in any::<[u8; 8]>()) {
        let variant = match bytes[0] % 4 {
            0 => X509Negative::Expired,
            1 => X509Negative::NotYetValid,
            2 => X509Negative::WrongKeyUsage,
            _ => X509Negative::SelfSignedButClaimsCA,
        };
        assert!(!variant.variant_name().is_empty());
    }

    #[test]
    fn chain_negative_variant_names_are_stable_over_random_data(data in any::<Vec<u8>>()) {
        let host = make_ascii_label(&data);
        let base = ChainSpec::new(&host);

        let variants = [
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
            ChainNegative::HostnameMismatch {
                wrong_hostname: format!("{host}-wrong"),
            },
        ];

        for variant in &variants {
            let first = variant.apply_to_spec(&base);
            let second = variant.apply_to_spec(&base);
            assert_eq!(first, second);
            assert!(!variant.variant_name().is_empty());
        }
    }
}
