#![forbid(unsafe_code)]

//! Criterion benchmarks for the hot paths in the uselesskey workspace.
//!
//! Run with: `cargo bench -p uselesskey --features full`

use criterion::{Criterion, criterion_group, criterion_main};
use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt, HmacSpec,
    RsaFactoryExt, RsaSpec, Seed, X509FactoryExt, X509Spec,
};

// ── RSA key generation (the biggest hot path) ───────────────────────

fn bench_rsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_keygen");
    group.sample_size(10);

    group.bench_function("2048", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.rsa("bench", RsaSpec::rs256()),
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("4096", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.rsa("bench", RsaSpec::new(4096)),
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

// ── ECDSA P-256 / P-384 key generation ──────────────────────────────

fn bench_ecdsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_keygen");

    group.bench_function("p256", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.ecdsa("bench", EcdsaSpec::es256()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("p384", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.ecdsa("bench", EcdsaSpec::es384()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Ed25519 key generation ──────────────────────────────────────────

fn bench_ed25519_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_keygen");

    group.bench_function("ed25519", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.ed25519("bench", Ed25519Spec::new()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── HMAC key generation ─────────────────────────────────────────────

fn bench_hmac_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_keygen");

    group.bench_function("hs256", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.hmac("bench", HmacSpec::hs256()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("hs384", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.hmac("bench", HmacSpec::hs384()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("hs512", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.hmac("bench", HmacSpec::hs512()),
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── X.509 self-signed certificate generation ────────────────────────

fn bench_x509_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("x509_generation");
    group.sample_size(10);

    group.bench_function("self_signed_2048", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.x509_self_signed("bench", X509Spec::self_signed("bench.example.com")),
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

// ── Factory cache: hit vs miss ──────────────────────────────────────

fn bench_cache_hit_vs_miss(c: &mut Criterion) {
    // Cache miss: fresh factory ⇒ forces full RSA keygen each iteration
    {
        let mut group = c.benchmark_group("cache/miss");
        group.sample_size(10);

        group.bench_function("rsa_2048", |b| {
            b.iter_batched(
                Factory::random,
                |fx| fx.rsa("bench", RsaSpec::rs256()),
                criterion::BatchSize::PerIteration,
            );
        });

        group.finish();
    }

    // Cache hit: reuse factory, key already materialised
    {
        let mut group = c.benchmark_group("cache/hit");

        let fx = Factory::random();
        let _ = fx.rsa("bench", RsaSpec::rs256()); // prime the cache

        group.bench_function("rsa_2048", |b| {
            b.iter(|| fx.rsa("bench", RsaSpec::rs256()));
        });

        group.finish();
    }
}

// ── Deterministic vs random mode ────────────────────────────────────

fn bench_deterministic_vs_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("deterministic_vs_random");
    group.sample_size(10);

    group.bench_function("rsa_2048_random", |b| {
        b.iter_batched(
            Factory::random,
            |fx| fx.rsa("bench", RsaSpec::rs256()),
            criterion::BatchSize::PerIteration,
        );
    });

    let seed = Seed::from_env_value("bench-seed").expect("valid seed");
    group.bench_function("rsa_2048_deterministic", |b| {
        b.iter_batched(
            || Factory::deterministic(seed),
            |fx| fx.rsa("bench", RsaSpec::rs256()),
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

// ── Criterion wiring ────────────────────────────────────────────────

criterion_group!(
    keygen,
    bench_rsa_keygen,
    bench_ecdsa_keygen,
    bench_ed25519_keygen,
    bench_hmac_keygen,
    bench_x509_generation,
    bench_cache_hit_vs_miss,
    bench_deterministic_vs_random,
);

criterion_main!(keygen);
