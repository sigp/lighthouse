use kzg::{
    Blob as KzgBlob, Bytes48, CellRef as KzgCellRef, CellsAndKzgProofs, Error as KzgError, Kzg,
};
use rayon::prelude::*;
use ssz_types::FixedVector;
use std::sync::Arc;
use types::beacon_block_body::KzgCommitments;
use types::data_column_sidecar::{Cell, DataColumn, DataColumnSidecarError};
use types::{
    Blob, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec, Hash256,
    KzgCommitment, KzgProof, KzgProofs, SignedBeaconBlock, SignedBeaconBlockHeader,
};

/// Converts a blob ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_blob_to_crypto_blob<E: EthSpec>(blob: &Blob<E>) -> Result<KzgBlob, KzgError> {
    KzgBlob::from_bytes(blob.as_ref()).map_err(Into::into)
}

fn ssz_blob_to_crypto_blob_boxed<E: EthSpec>(blob: &Blob<E>) -> Result<Box<KzgBlob>, KzgError> {
    ssz_blob_to_crypto_blob::<E>(blob).map(Box::new)
}

/// Converts a cell ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_cell_to_crypto_cell<E: EthSpec>(cell: &Cell<E>) -> Result<KzgCellRef, KzgError> {
    let cell_bytes: &[u8] = cell.as_ref();
    Ok(cell_bytes
        .try_into()
        .expect("expected cell to have size {BYTES_PER_CELL}. This should be guaranteed by the `FixedVector type"))
}

/// Validate a single blob-commitment-proof triplet from a `BlobSidecar`.
pub fn validate_blob<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
) -> Result<(), KzgError> {
    let _timer = crate::metrics::start_timer(&crate::metrics::KZG_VERIFICATION_SINGLE_TIMES);
    let kzg_blob = ssz_blob_to_crypto_blob_boxed::<E>(blob)?;
    kzg.verify_blob_kzg_proof(&kzg_blob, kzg_commitment, kzg_proof)
}

/// Validate a batch of `DataColumnSidecar`.
pub fn validate_data_columns<'a, E: EthSpec, I>(
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

    let column_indices = data_column_iter
        .clone()
        .flat_map(|data_column| {
            let col_index = data_column.index;
            data_column.column.iter().map(move |_| col_index)
        })
        .collect::<Vec<ColumnIndex>>();

    let commitments = data_column_iter
        .clone()
        .flat_map(|data_column| {
            data_column
                .kzg_commitments
                .iter()
                .map(|&commitment| Bytes48::from(commitment))
        })
        .collect::<Vec<_>>();

    kzg.verify_cell_proof_batch(&cells, &proofs, column_indices, &commitments)
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
    let kzg_blob = ssz_blob_to_crypto_blob_boxed::<E>(blob)?;
    kzg.compute_blob_kzg_proof(&kzg_blob, kzg_commitment)
}

/// Compute the kzg commitment for a given blob.
pub fn blob_to_kzg_commitment<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
) -> Result<KzgCommitment, KzgError> {
    let kzg_blob = ssz_blob_to_crypto_blob_boxed::<E>(blob)?;
    kzg.blob_to_kzg_commitment(&kzg_blob)
}

/// Compute the kzg proof for a given blob and an evaluation point z.
pub fn compute_kzg_proof<E: EthSpec>(
    kzg: &Kzg,
    blob: &Blob<E>,
    z: Hash256,
) -> Result<(KzgProof, Hash256), KzgError> {
    let z = z.0.into();
    let kzg_blob = ssz_blob_to_crypto_blob_boxed::<E>(blob)?;
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

/// Build data column sidecars from a signed beacon block and its blobs.
pub fn blobs_to_data_column_sidecars<E: EthSpec>(
    blobs: &[&Blob<E>],
    block: &SignedBeaconBlock<E>,
    kzg: &Kzg,
    spec: &ChainSpec,
) -> Result<DataColumnSidecarList<E>, DataColumnSidecarError> {
    if blobs.is_empty() {
        return Ok(vec![]);
    }

    let kzg_commitments = block
        .message()
        .body()
        .blob_kzg_commitments()
        .map_err(|_err| DataColumnSidecarError::PreDeneb)?;
    let kzg_commitments_inclusion_proof = block.message().body().kzg_commitments_merkle_proof()?;
    let signed_block_header = block.signed_block_header();

    // NOTE: assumes blob sidecars are ordered by index
    let blob_cells_and_proofs_vec = blobs
        .into_par_iter()
        .map(|blob| {
            let blob = blob
                .as_ref()
                .try_into()
                .expect("blob should have a guaranteed size due to FixedVector");
            kzg.compute_cells_and_proofs(blob)
        })
        .collect::<Result<Vec<_>, KzgError>>()?;

    build_data_column_sidecars(
        kzg_commitments.clone(),
        kzg_commitments_inclusion_proof,
        signed_block_header,
        blob_cells_and_proofs_vec,
        spec,
    )
    .map_err(DataColumnSidecarError::BuildSidecarFailed)
}

fn build_data_column_sidecars<E: EthSpec>(
    kzg_commitments: KzgCommitments<E>,
    kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
    signed_block_header: SignedBeaconBlockHeader,
    blob_cells_and_proofs_vec: Vec<CellsAndKzgProofs>,
    spec: &ChainSpec,
) -> Result<DataColumnSidecarList<E>, String> {
    let number_of_columns = spec.number_of_columns;
    let mut columns = vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];
    let mut column_kzg_proofs =
        vec![Vec::with_capacity(E::max_blobs_per_block()); number_of_columns];

    for (blob_cells, blob_cell_proofs) in blob_cells_and_proofs_vec {
        // we iterate over each column, and we construct the column from "top to bottom",
        // pushing on the cell and the corresponding proof at each column index. we do this for
        // each blob (i.e. the outer loop).
        for col in 0..number_of_columns {
            let cell = blob_cells
                .get(col)
                .ok_or(format!("Missing blob cell at index {col}"))?;
            let cell: Vec<u8> = cell.to_vec();
            let cell = Cell::<E>::from(cell);

            let proof = blob_cell_proofs
                .get(col)
                .ok_or(format!("Missing blob cell KZG proof at index {col}"))?;

            let column = columns
                .get_mut(col)
                .ok_or(format!("Missing data column at index {col}"))?;
            let column_proofs = column_kzg_proofs
                .get_mut(col)
                .ok_or(format!("Missing data column proofs at index {col}"))?;

            column.push(cell);
            column_proofs.push(*proof);
        }
    }

    let sidecars: Vec<Arc<DataColumnSidecar<E>>> = columns
        .into_iter()
        .zip(column_kzg_proofs)
        .enumerate()
        .map(|(index, (col, proofs))| {
            Arc::new(DataColumnSidecar {
                index: index as u64,
                column: DataColumn::<E>::from(col),
                kzg_commitments: kzg_commitments.clone(),
                kzg_proofs: KzgProofs::<E>::from(proofs),
                signed_block_header: signed_block_header.clone(),
                kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
            })
        })
        .collect();

    Ok(sidecars)
}

/// Reconstruct all data columns from a subset of data column sidecars (requires at least 50%).
pub fn reconstruct_data_columns<E: EthSpec>(
    kzg: &Kzg,
    data_columns: &[Arc<DataColumnSidecar<E>>],
    spec: &ChainSpec,
) -> Result<DataColumnSidecarList<E>, KzgError> {
    let first_data_column = data_columns
        .first()
        .ok_or(KzgError::InconsistentArrayLength(
            "data_columns should have at least one element".to_string(),
        ))?;
    let num_of_blobs = first_data_column.kzg_commitments.len();

    let blob_cells_and_proofs_vec =
        (0..num_of_blobs)
            .into_par_iter()
            .map(|row_index| {
                let mut cells: Vec<KzgCellRef> = vec![];
                let mut cell_ids: Vec<u64> = vec![];
                for data_column in data_columns {
                    let cell = data_column.column.get(row_index).ok_or(
                        KzgError::InconsistentArrayLength(format!(
                            "Missing data column at index {row_index}"
                        )),
                    )?;

                    cells.push(ssz_cell_to_crypto_cell::<E>(cell)?);
                    cell_ids.push(data_column.index);
                }
                kzg.recover_cells_and_compute_kzg_proofs(&cell_ids, &cells)
            })
            .collect::<Result<Vec<_>, KzgError>>()?;

    // Clone sidecar elements from existing data column, no need to re-compute
    build_data_column_sidecars(
        first_data_column.kzg_commitments.clone(),
        first_data_column.kzg_commitments_inclusion_proof.clone(),
        first_data_column.signed_block_header.clone(),
        blob_cells_and_proofs_vec,
        spec,
    )
    .map_err(KzgError::ReconstructFailed)
}

#[cfg(test)]
mod test {
    use crate::kzg_utils::{blobs_to_data_column_sidecars, reconstruct_data_columns};
    use bls::Signature;
    use kzg::{trusted_setup::get_trusted_setup, Kzg, KzgCommitment, TrustedSetup};
    use types::{
        beacon_block_body::KzgCommitments, BeaconBlock, BeaconBlockDeneb, Blob, BlobsList,
        ChainSpec, EmptyBlock, EthSpec, MainnetEthSpec, SignedBeaconBlock,
    };

    type E = MainnetEthSpec;

    // Loading and initializing PeerDAS KZG is expensive and slow, so we group the tests together
    // only load it once.
    #[test]
    fn test_build_data_columns_sidecars() {
        let spec = E::default_spec();
        let kzg = get_kzg();
        test_build_data_columns_empty(&kzg, &spec);
        test_build_data_columns(&kzg, &spec);
        test_reconstruct_data_columns(&kzg, &spec);
    }

    #[track_caller]
    fn test_build_data_columns_empty(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 0;
        let (signed_block, blobs) = create_test_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, &signed_block, kzg, spec).unwrap();
        assert!(column_sidecars.is_empty());
    }

    #[track_caller]
    fn test_build_data_columns(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 6;
        let (signed_block, blobs) = create_test_block_and_blobs::<E>(num_of_blobs, spec);

        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, &signed_block, kzg, spec).unwrap();

        let block_kzg_commitments = signed_block
            .message()
            .body()
            .blob_kzg_commitments()
            .unwrap()
            .clone();
        let block_kzg_commitments_inclusion_proof = signed_block
            .message()
            .body()
            .kzg_commitments_merkle_proof()
            .unwrap();

        assert_eq!(column_sidecars.len(), spec.number_of_columns);
        for (idx, col_sidecar) in column_sidecars.iter().enumerate() {
            assert_eq!(col_sidecar.index, idx as u64);

            assert_eq!(col_sidecar.kzg_commitments.len(), num_of_blobs);
            assert_eq!(col_sidecar.column.len(), num_of_blobs);
            assert_eq!(col_sidecar.kzg_proofs.len(), num_of_blobs);

            assert_eq!(col_sidecar.kzg_commitments, block_kzg_commitments);
            assert_eq!(
                col_sidecar.kzg_commitments_inclusion_proof,
                block_kzg_commitments_inclusion_proof
            );
            assert!(col_sidecar.verify_inclusion_proof());
        }
    }

    #[track_caller]
    fn test_reconstruct_data_columns(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 6;
        let (signed_block, blobs) = create_test_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, &signed_block, kzg, spec).unwrap();

        // Now reconstruct
        let reconstructed_columns = reconstruct_data_columns(
            kzg,
            &column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2],
            spec,
        )
        .unwrap();

        for i in 0..spec.number_of_columns {
            assert_eq!(reconstructed_columns.get(i), column_sidecars.get(i), "{i}");
        }
    }

    fn get_kzg() -> Kzg {
        let trusted_setup: TrustedSetup = serde_json::from_reader(get_trusted_setup().as_slice())
            .map_err(|e| format!("Unable to read trusted setup file: {}", e))
            .expect("should have trusted setup");
        Kzg::new_from_trusted_setup_das_enabled(trusted_setup).expect("should create kzg")
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
