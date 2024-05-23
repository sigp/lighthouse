use kzg::{Blob as KzgBlob, Bytes48, Cell as KzgCell, Error as KzgError, Kzg};
use std::sync::Arc;
use types::data_column_sidecar::Cell;
use types::{Blob, DataColumnSidecar, EthSpec, Hash256, KzgCommitment, KzgProof};

/// Converts a blob ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_blob_to_crypto_blob<E: EthSpec>(blob: &Blob<E>) -> Result<KzgBlob, KzgError> {
    KzgBlob::from_bytes(blob.as_ref()).map_err(Into::into)
}

/// Converts a cell ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_cell_to_crypto_cell<E: EthSpec>(cell: &Cell<E>) -> Result<KzgCell, KzgError> {
    KzgCell::from_bytes(cell.as_ref()).map_err(Into::into)
}

/// Validate a single blob-commitment-proof triplet from a `BlobSidecar`.
pub fn validate_blob<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
) -> Result<(), KzgError> {
    let _timer = crate::metrics::start_timer(&crate::metrics::KZG_VERIFICATION_SINGLE_TIMES);
    let kzg_blob = ssz_blob_to_crypto_blob::<E>(blob)?;
    kzg.verify_blob_kzg_proof(&kzg_blob, kzg_commitment, kzg_proof)
}

/// Validate a batch of `DataColumnSidecar`.
pub fn validate_data_column<'a, E: EthSpec, I>(
    kzg: &Kzg,
    data_column_iter: I,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    let cells = data_column_iter
        .clone()
        .flat_map(|data_column| data_column.column.iter().map(ssz_cell_to_crypto_cell::<E>))
        .collect::<Result<Vec<_>, KzgError>>()?;

    let proofs = data_column_iter
        .clone()
        .flat_map(|data_column| {
            data_column
                .kzg_proofs
                .iter()
                .map(|&proof| Bytes48::from(proof))
        })
        .collect::<Vec<_>>();

    let coordinates = data_column_iter
        .clone()
        .flat_map(|data_column| {
            let col_index = data_column.index;
            (0..data_column.column.len()).map(move |row| (row as u64, col_index))
        })
        .collect::<Vec<(u64, u64)>>();

    let commitments = data_column_iter
        .clone()
        .flat_map(|data_column| {
            data_column
                .kzg_commitments
                .iter()
                .map(|&commitment| Bytes48::from(commitment))
        })
        .collect::<Vec<_>>();

    kzg.verify_cell_proof_batch(&cells, &proofs, &coordinates, &commitments)
}

/// Validate a batch of blob-commitment-proof triplets from multiple `BlobSidecars`.
pub fn validate_blobs<E: EthSpec>(
    kzg: &Kzg,
    expected_kzg_commitments: &[KzgCommitment],
    blobs: Vec<&Blob<E>>,
    kzg_proofs: &[KzgProof],
) -> Result<(), KzgError> {
    let _timer = crate::metrics::start_timer(&crate::metrics::KZG_VERIFICATION_BATCH_TIMES);
    let blobs = blobs
        .into_iter()
        .map(|blob| ssz_blob_to_crypto_blob::<E>(blob))
        .collect::<Result<Vec<_>, KzgError>>()?;

    kzg.verify_blob_kzg_proof_batch(&blobs, expected_kzg_commitments, kzg_proofs)
}

/// Compute the kzg proof given an ssz blob and its kzg commitment.
pub fn compute_blob_kzg_proof<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
    kzg_commitment: KzgCommitment,
) -> Result<KzgProof, KzgError> {
    let kzg_blob = ssz_blob_to_crypto_blob::<E>(blob)?;
    kzg.compute_blob_kzg_proof(&kzg_blob, kzg_commitment)
}

/// Compute the kzg commitment for a given blob.
pub fn blob_to_kzg_commitment<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
) -> Result<KzgCommitment, KzgError> {
    let kzg_blob = ssz_blob_to_crypto_blob::<E>(blob)?;
    kzg.blob_to_kzg_commitment(&kzg_blob)
}

/// Compute the kzg proof for a given blob and an evaluation point z.
pub fn compute_kzg_proof<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
    z: Hash256,
) -> Result<(KzgProof, Hash256), KzgError> {
    let z = z.0.into();
    let kzg_blob = ssz_blob_to_crypto_blob::<E>(blob)?;
    kzg.compute_kzg_proof(&kzg_blob, &z)
        .map(|(proof, z)| (proof, Hash256::from_slice(&z.to_vec())))
}

/// Verify a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
pub fn verify_kzg_proof<E: EthSpec>(
    kzg: &Kzg,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
    z: Hash256,
    y: Hash256,
) -> Result<bool, KzgError> {
    kzg.verify_kzg_proof(kzg_commitment, &z.0.into(), &y.0.into(), kzg_proof)
}

#[cfg(test)]
mod test {
    use bls::Signature;
    use eth2_network_config::TRUSTED_SETUP_BYTES;
    use kzg::{Kzg, KzgCommitment, TrustedSetup};
    use types::{
        beacon_block_body::KzgCommitments, BeaconBlock, BeaconBlockDeneb, Blob, BlobsList,
        ChainSpec, DataColumnSidecar, EmptyBlock, EthSpec, MainnetEthSpec, SignedBeaconBlock,
    };

    #[test]
    fn build_and_reconstruct() {
        type E = MainnetEthSpec;
        let num_of_blobs = 6;
        let spec = E::default_spec();
        let (signed_block, blob_sidecars) = create_test_block_and_blobs::<E>(num_of_blobs, &spec);

        let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP_BYTES)
            .map_err(|e| format!("Unable to read trusted setup file: {}", e))
            .expect("should have trusted setup");
        let kzg = Kzg::new_from_trusted_setup(trusted_setup).expect("should create kzg");

        let column_sidecars =
            DataColumnSidecar::build_sidecars(&blob_sidecars, &signed_block, &kzg, &spec).unwrap();

        // Now reconstruct
        let reconstructed_columns = DataColumnSidecar::reconstruct(
            &kzg,
            &column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2],
            &spec,
        )
        .unwrap();

        for i in 0..spec.number_of_columns {
            assert_eq!(reconstructed_columns.get(i), column_sidecars.get(i), "{i}");
        }
    }

    fn create_test_block_and_blobs<E: EthSpec>(
        num_of_blobs: usize,
        spec: &ChainSpec,
    ) -> (SignedBeaconBlock<E>, BlobsList<E>) {
        let mut block = BeaconBlock::Deneb(BeaconBlockDeneb::empty(spec));
        let mut body = block.body_mut();
        let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
        *blob_kzg_commitments =
            KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs])
                .unwrap();

        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());

        let blobs = (0..num_of_blobs)
            .map(|_| Blob::<E>::default())
            .collect::<Vec<_>>()
            .into();

        (signed_block, blobs)
    }
}
