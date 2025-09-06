use std::sync::Arc;

use beacon_chain::kzg_utils::{blobs_to_data_column_sidecars, reconstruct_data_columns};
use beacon_chain::test_utils::get_kzg;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use bls::Signature;
use kzg::{KzgCommitment, KzgProof};
use types::{
    BeaconBlock, BeaconBlockFulu, Blob, BlobsList, ChainSpec, EmptyBlock, EthSpec, KzgProofs,
    MainnetEthSpec, SignedBeaconBlock, beacon_block_body::KzgCommitments,
};

fn create_test_block_and_blobs<E: EthSpec>(
    num_of_blobs: usize,
    spec: &ChainSpec,
) -> (SignedBeaconBlock<E>, BlobsList<E>, KzgProofs<E>) {
    let mut block = BeaconBlock::Fulu(BeaconBlockFulu::empty(spec));
    let mut body = block.body_mut();
    let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
    *blob_kzg_commitments =
        KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs]).unwrap();

    let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

    let blobs = (0..num_of_blobs)
        .map(|_| Blob::<E>::default())
        .collect::<Vec<_>>()
        .into();
    let proofs = vec![KzgProof::empty(); num_of_blobs * E::number_of_columns()].into();

    (signed_block, blobs, proofs)
}

fn all_benches(c: &mut Criterion) {
    type E = MainnetEthSpec;
    let spec = Arc::new(E::default_spec());

    let kzg = get_kzg(&spec);
    for blob_count in [1, 2, 3, 6] {
        let (signed_block, blobs, proofs) = create_test_block_and_blobs::<E>(blob_count, &spec);

        let column_sidecars = blobs_to_data_column_sidecars(
            &blobs.iter().collect::<Vec<_>>(),
            proofs.to_vec(),
            &signed_block,
            &kzg,
            &spec,
        )
        .unwrap();

        let spec = spec.clone();

        c.bench_function(&format!("reconstruct_{}", blob_count), |b| {
            b.iter(|| {
                black_box(reconstruct_data_columns(
                    &kzg,
                    column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2].to_vec(),
                    spec.as_ref(),
                ))
            })
        });
    }
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
