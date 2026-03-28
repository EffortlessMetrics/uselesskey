use uselesskey::{Factory, TokenFactoryExt, TokenSpec};

fn main() {
    let fx = Factory::deterministic_from_str("api-key-fixtures");
    let token = fx.token("svc-api", TokenSpec::api_key());

    assert!(token.value().starts_with("uk_test_"));
}

#[cfg(test)]
mod tests {
    use uselesskey::{Factory, TokenFactoryExt, TokenSpec};

    #[test]
    fn quick_start_token_snippet_still_works() {
        let fx = Factory::deterministic_from_str("api-key-fixtures");
        let token = fx.token("svc-api", TokenSpec::api_key());

        assert!(token.value().starts_with("uk_test_"));
    }
}
