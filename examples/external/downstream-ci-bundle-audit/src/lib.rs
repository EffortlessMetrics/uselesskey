#![forbid(unsafe_code)]

/// Marker for the downstream CI bundle audit example.
///
/// The example's primary behavior lives in the workflow file. This crate exists
/// so external-adoption smoke can copy the example into a clean project and
/// compile it like the other external examples.
pub fn example_name() -> &'static str {
    "downstream-ci-bundle-audit"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_downstream_ci_bundle_audit_example() {
        assert_eq!(example_name(), "downstream-ci-bundle-audit");
    }
}
