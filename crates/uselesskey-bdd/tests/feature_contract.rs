use std::collections::BTreeSet;

use uselesskey_test_grid::{BDD_FEATURE_MATRIX, FeatureSet, UK_FEATURE_SETS};

const BDD_MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn bdd_feature_contract_and_grid_are_in_sync() {
    let declared = declared_bdd_features(BDD_MANIFEST);

    for expected in UK_FEATURE_SETS {
        assert!(
            declared.contains(*expected),
            "bdd manifest does not declare uk feature '{expected}'"
        );
    }

    let matrix_features = matrix_feature_tokens(BDD_FEATURE_MATRIX);
    for feature in matrix_features {
        assert!(
            declared.contains(feature.as_str()),
            "bdd feature matrix references undeclared uk feature '{feature}'"
        );
    }
}

fn declared_bdd_features(manifest: &str) -> BTreeSet<String> {
    let mut in_features = false;
    let mut features = BTreeSet::new();

    for line in manifest.lines() {
        let trimmed = line.trim();

        if trimmed == "[features]" {
            in_features = true;
            continue;
        }

        if !in_features {
            continue;
        }

        if trimmed.starts_with('[') && !trimmed.is_empty() {
            break;
        }

        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };

        let name = name.trim();
        if name.starts_with("uk-") {
            features.insert(name.to_string());
        }
    }

    features
}

fn matrix_feature_tokens(matrix: &[FeatureSet]) -> BTreeSet<String> {
    let mut features = BTreeSet::new();

    for entry in matrix {
        let mut args = entry.cargo_args.iter().peekable();
        while let Some(arg) = args.next() {
            if *arg != "--features" {
                continue;
            }

            if let Some(values) = args.next() {
                for feature in values.split(',') {
                    if feature.starts_with("uk-") {
                        features.insert(feature.to_string());
                    }
                }
            }
        }
    }

    features
}
