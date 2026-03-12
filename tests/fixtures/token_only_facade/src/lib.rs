#[cfg(test)]
mod tests {
    use uselesskey::{Factory, TokenFactoryExt, TokenSpec};

    #[test]
    fn token_only_facade_smoke() {
        let fx = Factory::deterministic_from_str("token-only-fixtures");
        let token = fx.token("svc-api", TokenSpec::api_key());
        assert!(!token.value().is_empty());
    }
}
