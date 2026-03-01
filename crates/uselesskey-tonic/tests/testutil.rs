#![allow(unused)]

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

pub(crate) fn fx() -> Factory {
    FX.get_or_init(|| Factory::deterministic(Seed::new([0xAB; 32])))
        .clone()
}
