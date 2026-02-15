use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

pub fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-x509-ext-test-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}
