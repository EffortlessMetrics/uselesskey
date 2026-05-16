#![forbid(unsafe_code)]

mod srp;

fn main() -> anyhow::Result<()> {
    srp::run()
}
