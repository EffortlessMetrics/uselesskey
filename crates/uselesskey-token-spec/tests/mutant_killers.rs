use uselesskey_token_spec::TokenSpec;

#[test]
fn constructors_return_correct_variants() {
    assert_eq!(TokenSpec::api_key(), TokenSpec::ApiKey);
    assert_eq!(TokenSpec::bearer(), TokenSpec::Bearer);
    assert_eq!(TokenSpec::oauth_access_token(), TokenSpec::OAuthAccessToken);
}

#[test]
fn kind_names_exact() {
    assert_eq!(TokenSpec::ApiKey.kind_name(), "api_key");
    assert_eq!(TokenSpec::Bearer.kind_name(), "bearer");
    assert_eq!(
        TokenSpec::OAuthAccessToken.kind_name(),
        "oauth_access_token"
    );
}

#[test]
fn stable_bytes_exact() {
    assert_eq!(TokenSpec::ApiKey.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(TokenSpec::Bearer.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(TokenSpec::OAuthAccessToken.stable_bytes(), [0, 0, 0, 3]);
}

#[test]
fn kind_names_are_all_distinct() {
    let names = [
        TokenSpec::ApiKey.kind_name(),
        TokenSpec::Bearer.kind_name(),
        TokenSpec::OAuthAccessToken.kind_name(),
    ];
    assert_ne!(names[0], names[1]);
    assert_ne!(names[0], names[2]);
    assert_ne!(names[1], names[2]);
}
