use std::hint::black_box;
use std::sync::Arc;

use beacon_chain::kzg_utils::{blobs_to_data_column_sidecars, reconstruct_data_columns};
use beacon_chain::test_utils::get_kzg;
use criterion::{Criterion, criterion_group, criterion_main};

use bls::Signature;
use kzg::{KzgCommitment, KzgProof};
use types::{
    BeaconBlock, BeaconBlockFulu, Blob, BlobsList, ChainSpec, EmptyBlock, KzgProofs,
    SignedBeaconBlock, Spec, kzg_ext::KzgCommitments,
};

fn create_test_block_and_blobs(
    num_of_blobs: usize,
    spec: &ChainSpec,
) -> (SignedBeaconBlock, BlobsList, KzgProofs) {
    let mut block = BeaconBlock::Fulu(BeaconBlockFulu::empty(spec));
    let mut body = block.body_mut();
    let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
    *blob_kzg_commitments =
        KzgCommitments::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs]).unwrap();

    let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

    let blobs = (0..num_of_blobs)
        .map(|_| Blob::default())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let proofs = vec![KzgProof::empty(); num_of_blobs * Spec::NUMBER_OF_COLUMNS]
        .try_into()
        .unwrap();

    (signed_block, blobs, proofs)
}

fn all_benches(c: &mut Criterion) {
    let spec = Arc::new(Spec::default_spec());

    let kzg = get_kzg(&spec);
    for blob_count in [1, 2, 3, 6] {
        let (signed_block, blobs, proofs) = create_test_block_and_blobs(blob_count, &spec);

        let column_sidecars = blobs_to_data_column_sidecars(
            &blobs.iter().collect::<Vec<_>>(),
            proofs.to_vec(),
            &signed_block,
            &kzg,
            &spec,
        )
        .unwrap();

        let kzg_commitments = signed_block
            .message()
            .body()
            .blob_kzg_commitments()
            .unwrap()
            .clone();

        let spec = spec.clone();

        c.bench_function(&format!("reconstruct_{}", blob_count), |b| {
            b.iter(|| {
                black_box(reconstruct_data_columns(
                    &kzg,
                    column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2].to_vec(),
                    &kzg_commitments,
                    spec.as_ref(),
                ))
            })
        });
    }
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
