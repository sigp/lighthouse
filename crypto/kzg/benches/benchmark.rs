use c_kzg::KzgSettings;
use criterion::{criterion_group, criterion_main, Criterion};
use kzg::{trusted_setup::get_trusted_setup, TrustedSetup, NO_PRECOMPUTE};
use rust_eth_kzg::{DASContext, TrustedSetup as PeerDASTrustedSetup};

pub fn bench_init_context(c: &mut Criterion) {
    let trusted_setup_bytes = get_trusted_setup();
    let trusted_setup_json = std::str::from_utf8(&trusted_setup_bytes)
        .map_err(|e| format!("Unable to read trusted setup file: {}", e))
        .expect("should have trusted setup");

    c.bench_function("Initialize context rust_eth_kzg", |b| {
        b.iter(|| {
            let trusted_setup = PeerDASTrustedSetup::from_json(trusted_setup_json);
            DASContext::new(
                &trusted_setup,
                rust_eth_kzg::UsePrecomp::Yes {
                    width: rust_eth_kzg::constants::RECOMMENDED_PRECOMP_WIDTH,
                },
            )
        })
    });
    c.bench_function("Initialize context c-kzg (4844)", |b| {
        b.iter(|| {
            let trusted_setup: TrustedSetup =
                serde_json::from_reader(trusted_setup_bytes.as_slice())
                    .map_err(|e| format!("Unable to read trusted setup file: {}", e))
                    .expect("should have trusted setup");
            KzgSettings::load_trusted_setup(
                &trusted_setup.g1_monomial(),
                &trusted_setup.g1_lagrange(),
                &trusted_setup.g2_monomial(),
                NO_PRECOMPUTE,
            )
            .unwrap()
        })
    });
}

criterion_group!(benches, bench_init_context);
criterion_main!(benches);
