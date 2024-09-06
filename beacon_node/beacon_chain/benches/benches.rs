use std::sync::Arc;

use beacon_chain::kzg_utils::{blobs_to_data_column_sidecars, reconstruct_data_columns};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bls::Signature;
use eth2_network_config::TRUSTED_SETUP_BYTES;
use kzg::{Kzg, KzgCommitment, TrustedSetup};
use types::{
    beacon_block_body::KzgCommitments, BeaconBlock, BeaconBlockDeneb, Blob, BlobsList, ChainSpec,
    EmptyBlock, EthSpec, MainnetEthSpec, SignedBeaconBlock,
};

fn create_test_block_and_blobs<E: EthSpec>(
    num_of_blobs: usize,
    spec: &ChainSpec,
) -> (SignedBeaconBlock<E>, BlobsList<E>) {
    let mut block = BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec));
    let mut body = block.body_mut();
    let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
    *blob_kzg_commitments =
        KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs]).unwrap();

    let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

    let blobs = (0..num_of_blobs)
        .map(|_| Blob::<E>::default())
        .collect::<Vec<_>>()
        .into();

    (signed_block, blobs)
}

fn all_benches(c: &mut Criterion) {
    type E = MainnetEthSpec;
    let spec = Arc::new(E::default_spec());

    let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP_BYTES)
        .map_err(|e| format!("Unable to read trusted setup file: {}", e))
        .expect("should have trusted setup");
    let kzg = Arc::new(Kzg::new_from_trusted_setup(trusted_setup).expect("should create kzg"));

    for blob_count in [1, 2, 3, 6] {
        let kzg = kzg.clone();
        let (signed_block, blob_sidecars) = create_test_block_and_blobs::<E>(blob_count, &spec);

        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_sidecars, &signed_block, &kzg.clone(), &spec)
                .unwrap();

        let spec = spec.clone();

        c.bench_function(&format!("reconstruct_{}", blob_count), |b| {
            b.iter(|| {
                black_box(reconstruct_data_columns(
                    &kzg,
                    &column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2],
                    spec.as_ref(),
                ))
            })
        });
    }
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
