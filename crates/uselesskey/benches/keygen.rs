#![forbid(unsafe_code)]

//! Criterion benchmarks for hot fixture paths.
//!
//! Run with:
//! - `cargo bench -p uselesskey --features full`
//! - `cargo xtask perf` for machine-readable CI summaries.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use uselesskey::negative::CorruptPem;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory,
    HmacFactoryExt, HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
    X509Spec,
};

fn bench_rsa_fixture_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_fixture_generation");
    group.sample_size(10);

    group.bench_function("cold_cache/rs256", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.rsa("bench-rsa", RsaSpec::rs256()),
            BatchSize::PerIteration,
        );
    });

    let fx = Factory::random();
    let _ = fx.rsa("bench-rsa", RsaSpec::rs256());
    group.bench_function("warm_cache/rs256", |b| {
        b.iter(|| fx.rsa("bench-rsa", RsaSpec::rs256()));
    });

    group.finish();
}

fn bench_ecdsa_fixture_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_fixture_generation");

    group.bench_function("cold_cache/es256", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.ecdsa("bench-ecdsa", EcdsaSpec::es256()),
            BatchSize::SmallInput,
        );
    });

    let fx = Factory::random();
    let _ = fx.ecdsa("bench-ecdsa", EcdsaSpec::es256());
    group.bench_function("warm_cache/es256", |b| {
        b.iter(|| fx.ecdsa("bench-ecdsa", EcdsaSpec::es256()));
    });

    group.finish();
}

fn bench_ed25519_fixture_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_fixture_generation");

    group.bench_function("cold_cache", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.ed25519("bench-ed25519", Ed25519Spec::new()),
            BatchSize::SmallInput,
        );
    });

    let fx = Factory::random();
    let _ = fx.ed25519("bench-ed25519", Ed25519Spec::new());
    group.bench_function("warm_cache", |b| {
        b.iter(|| fx.ed25519("bench-ed25519", Ed25519Spec::new()));
    });

    group.finish();
}

fn bench_hmac_secret_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_secret_generation");

    group.bench_function("cold_cache/hs512", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.hmac("bench-hmac", HmacSpec::hs512()),
            BatchSize::SmallInput,
        );
    });

    let fx = Factory::random();
    let _ = fx.hmac("bench-hmac", HmacSpec::hs512());
    group.bench_function("warm_cache/hs512", |b| {
        b.iter(|| fx.hmac("bench-hmac", HmacSpec::hs512()));
    });

    group.finish();
}

fn bench_token_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_generation");

    group.bench_function("cold_cache/oauth", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.token("bench-token", TokenSpec::oauth_access_token()),
            BatchSize::SmallInput,
        );
    });

    let fx = Factory::random();
    let _ = fx.token("bench-token", TokenSpec::oauth_access_token());
    group.bench_function("warm_cache/oauth", |b| {
        b.iter(|| fx.token("bench-token", TokenSpec::oauth_access_token()));
    });

    group.finish();
}

fn bench_x509_self_signed(c: &mut Criterion) {
    let mut group = c.benchmark_group("x509_self_signed");
    group.sample_size(10);

    group.bench_function("cold_cache", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.x509_self_signed("bench-cert", X509Spec::self_signed("bench.example.com")),
            BatchSize::PerIteration,
        );
    });

    let fx = Factory::random();
    let _ = fx.x509_self_signed("bench-cert", X509Spec::self_signed("bench.example.com"));
    group.bench_function("warm_cache", |b| {
        b.iter(|| fx.x509_self_signed("bench-cert", X509Spec::self_signed("bench.example.com")));
    });

    group.finish();
}

fn bench_x509_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("x509_chain");
    group.sample_size(10);

    group.bench_function("cold_cache", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com")),
            BatchSize::PerIteration,
        );
    });

    let fx = Factory::random();
    let _ = fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com"));
    group.bench_function("warm_cache", |b| {
        b.iter(|| fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com")));
    });

    group.finish();
}

fn bench_negative_fixture_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("negative_fixture_generation");

    group.bench_function("rsa_bad_base64", |b| {
        b.iter_batched(
            || {
                let fx = Factory::random();
                fx.rsa("bench-negative", RsaSpec::rs256())
            },
            |rsa| rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    keygen,
    bench_rsa_fixture_generation,
    bench_ecdsa_fixture_generation,
    bench_ed25519_fixture_generation,
    bench_hmac_secret_generation,
    bench_token_generation,
    bench_x509_self_signed,
    bench_x509_chain,
    bench_negative_fixture_generation,
);
criterion_main!(keygen);
