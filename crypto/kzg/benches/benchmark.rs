use c_kzg::KzgSettings;
use criterion::{criterion_group, criterion_main, Criterion};
use eth2_network_config::TRUSTED_SETUP_BYTES;
use kzg::TrustedSetup;
use rust_eth_kzg::{DASContext, TrustedSetup as PeerDASTrustedSetup};

pub fn bench_init_context(c: &mut Criterion) {
    c.bench_function(&format!("Initialize context rust_eth_kzg"), |b| {
        b.iter(|| {
            const NUM_THREADS: usize = 1;
            let trusted_setup = PeerDASTrustedSetup::default();
            DASContext::with_threads(&trusted_setup, NUM_THREADS)
        })
    });
    c.bench_function(&format!("Initialize context c-kzg (4844)"), |b| {
        b.iter(|| {
            let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP_BYTES)
                .map_err(|e| format!("Unable to read trusted setup file: {}", e))
                .expect("should have trusted setup");
            KzgSettings::load_trusted_setup(&trusted_setup.g1_points(), &trusted_setup.g2_points())
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_init_context);
criterion_main!(benches);
