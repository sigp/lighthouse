use kzg::{
    Blob as KzgBlob, Bytes48, Cell as KzgCell, CellRef as KzgCellRef, CellsAndKzgProofs,
    Error as KzgError, Kzg, KzgBlobRef,
};
use rayon::prelude::*;
use ssz_types::{FixedVector, VariableList};
use std::sync::Arc;
use tracing::instrument;
use types::beacon_block_body::KzgCommitments;
use types::data_column_sidecar::{Cell, DataColumn, DataColumnSidecarError};
use types::{
    Blob, BlobSidecar, BlobSidecarList, ChainSpec, DataColumnSidecar, DataColumnSidecarList,
    EthSpec, Hash256, KzgCommitment, KzgProof, SignedBeaconBlock, SignedBeaconBlockHeader,
    SignedBlindedBeaconBlock,
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
fn ssz_cell_to_crypto_cell<E: EthSpec>(cell: &Cell<E>) -> Result<KzgCellRef<'_>, KzgError> {
    let cell_bytes: &[u8] = cell.as_ref();
    cell_bytes
        .try_into()
        .map_err(|e| KzgError::InconsistentArrayLength(format!("expected cell to have size BYTES_PER_CELL. This should be guaranteed by the `FixedVector` type: {e:?}")))
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
) -> Result<(), (Option<u64>, KzgError)>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    let mut cells = Vec::new();
    let mut proofs = Vec::new();
    let mut column_indices = Vec::new();
    let mut commitments = Vec::new();

    for data_column in data_column_iter {
        let col_index = data_column.index;

        if data_column.column.is_empty() {
            return Err((Some(col_index), KzgError::KzgVerificationFailed));
        }

        for cell in &data_column.column {
            cells.push(ssz_cell_to_crypto_cell::<E>(cell).map_err(|e| (Some(col_index), e))?);
            column_indices.push(col_index);
        }

        for &proof in &data_column.kzg_proofs {
            proofs.push(Bytes48::from(proof));
        }

        for &commitment in &data_column.kzg_commitments {
            commitments.push(Bytes48::from(commitment));
        }

        let expected_len = column_indices.len();

        // We make this check at each iteration so that the error is attributable to a specific column
        if cells.len() != expected_len
            || proofs.len() != expected_len
            || commitments.len() != expected_len
        {
            return Err((
                Some(col_index),
                KzgError::InconsistentArrayLength("Invalid data column".to_string()),
            ));
        }
    }

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
#[instrument(skip_all, level = "debug", fields(blob_count = blobs.len()))]
pub fn blobs_to_data_column_sidecars<E: EthSpec>(
    blobs: &[&Blob<E>],
    cell_proofs: Vec<KzgProof>,
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

    if cell_proofs.len() != blobs.len() * E::number_of_columns() {
        return Err(DataColumnSidecarError::InvalidCellProofLength {
            expected: blobs.len() * E::number_of_columns(),
            actual: cell_proofs.len(),
        });
    }

    let proof_chunks = cell_proofs
        .chunks_exact(E::number_of_columns())
        .collect::<Vec<_>>();

    // NOTE: assumes blob sidecars are ordered by index
    let zipped: Vec<_> = blobs.iter().zip(proof_chunks).collect();
    let blob_cells_and_proofs_vec = zipped
        .into_par_iter()
        .map(|(blob, proofs)| {
            let blob = blob.as_ref().try_into().map_err(|e| {
                KzgError::InconsistentArrayLength(format!(
                    "blob should have a guaranteed size due to FixedVector: {e:?}"
                ))
            })?;

            kzg.compute_cells(blob).and_then(|cells| {
                let proofs = proofs.try_into().map_err(|e| {
                    KzgError::InconsistentArrayLength(format!(
                        "proof chunks should have exactly `number_of_columns` proofs: {e:?}"
                    ))
                })?;
                Ok((cells, proofs))
            })
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

pub fn compute_cells<E: EthSpec>(blobs: &[&Blob<E>], kzg: &Kzg) -> Result<Vec<KzgCell>, KzgError> {
    let cells_vec = blobs
        .into_par_iter()
        .map(|blob| {
            let blob: KzgBlobRef<'_> = blob.as_ref().try_into().map_err(|e| {
                KzgError::InconsistentArrayLength(format!(
                    "blob should have a guaranteed size due to FixedVector: {e:?}",
                ))
            })?;

            kzg.compute_cells(blob)
        })
        .collect::<Result<Vec<_>, KzgError>>()?;

    let cells_flattened: Vec<KzgCell> = cells_vec.into_iter().flatten().collect();
    Ok(cells_flattened)
}

pub(crate) fn build_data_column_sidecars<E: EthSpec>(
    kzg_commitments: KzgCommitments<E>,
    kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
    signed_block_header: SignedBeaconBlockHeader,
    blob_cells_and_proofs_vec: Vec<CellsAndKzgProofs>,
    spec: &ChainSpec,
) -> Result<DataColumnSidecarList<E>, String> {
    let number_of_columns = E::number_of_columns();
    let max_blobs_per_block = spec
        .max_blobs_per_block(signed_block_header.message.slot.epoch(E::slots_per_epoch()))
        as usize;
    let mut columns = vec![Vec::with_capacity(max_blobs_per_block); number_of_columns];
    let mut column_kzg_proofs = vec![Vec::with_capacity(max_blobs_per_block); number_of_columns];

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
                kzg_proofs: VariableList::from(proofs),
                signed_block_header: signed_block_header.clone(),
                kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
            })
        })
        .collect();

    Ok(sidecars)
}

/// Reconstruct blobs from a subset of data column sidecars (requires at least 50%).
///
/// If `blob_indices_opt` is `None`, this function attempts to reconstruct all blobs associated
/// with the block.
/// This function does NOT use rayon as this is primarily used by a non critical path in HTTP API
/// and it will be slow if the node needs to reconstruct the blobs
pub fn reconstruct_blobs<E: EthSpec>(
    kzg: &Kzg,
    data_columns: &[Arc<DataColumnSidecar<E>>],
    blob_indices_opt: Option<Vec<u64>>,
    signed_block: &SignedBlindedBeaconBlock<E>,
    spec: &ChainSpec,
) -> Result<BlobSidecarList<E>, String> {
    // The data columns are from the database, so we assume their correctness.
    let first_data_column = data_columns
        .first()
        .ok_or("data_columns should have at least one element".to_string())?;

    let blob_indices: Vec<usize> = match blob_indices_opt {
        Some(indices) => indices.into_iter().map(|i| i as usize).collect(),
        None => {
            let num_of_blobs = first_data_column.kzg_commitments.len();
            (0..num_of_blobs).collect()
        }
    };

    let blob_sidecars = blob_indices
        .into_iter()
        .map(|row_index| {
            let mut cells: Vec<KzgCellRef> = vec![];
            let mut cell_ids: Vec<u64> = vec![];
            for data_column in data_columns {
                let cell = data_column
                    .column
                    .get(row_index)
                    .ok_or(format!("Missing data column at row index {row_index}"))
                    .and_then(|cell| {
                        ssz_cell_to_crypto_cell::<E>(cell).map_err(|e| format!("{e:?}"))
                    })?;

                cells.push(cell);
                cell_ids.push(data_column.index);
            }

            let num_cells_original_blob = E::number_of_columns() / 2;
            let blob_bytes = if data_columns.len() < E::number_of_columns() {
                let (recovered_cells, _kzg_proofs) = kzg
                    .recover_cells_and_compute_kzg_proofs(&cell_ids, &cells)
                    .map_err(|e| {
                        format!("Failed to recover cells and compute KZG proofs: {e:?}")
                    })?;

                recovered_cells
                    .into_iter()
                    .take(num_cells_original_blob)
                    .flat_map(|cell| cell.into_iter())
                    .collect()
            } else {
                cells
                    .into_iter()
                    .take(num_cells_original_blob)
                    .flat_map(|cell| (*cell).into_iter())
                    .collect()
            };

            let blob = Blob::<E>::new(blob_bytes).map_err(|e| format!("{e:?}"))?;
            let kzg_proof = KzgProof::empty();

            BlobSidecar::<E>::new_with_existing_proof(
                row_index,
                blob,
                signed_block,
                first_data_column.signed_block_header.clone(),
                &first_data_column.kzg_commitments_inclusion_proof,
                kzg_proof,
            )
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let max_blobs = spec.max_blobs_per_block(signed_block.epoch()) as usize;

    BlobSidecarList::new(blob_sidecars, max_blobs).map_err(|e| format!("{e:?}"))
}

/// Reconstruct all data columns from a subset of data column sidecars (requires at least 50%).
pub fn reconstruct_data_columns<E: EthSpec>(
    kzg: &Kzg,
    mut data_columns: Vec<Arc<DataColumnSidecar<E>>>,
    spec: &ChainSpec,
) -> Result<DataColumnSidecarList<E>, KzgError> {
    // Sort data columns by index to ensure ascending order for KZG operations
    data_columns.sort_unstable_by_key(|dc| dc.index);

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
                for data_column in &data_columns {
                    let cell = data_column.column.get(row_index).ok_or(
                        KzgError::InconsistentArrayLength(format!(
                            "Missing data column at row index {row_index}"
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
    use crate::kzg_utils::{
        blobs_to_data_column_sidecars, reconstruct_blobs, reconstruct_data_columns,
        validate_data_columns,
    };
    use bls::Signature;
    use eth2::types::BlobsBundle;
    use execution_layer::test_utils::generate_blobs;
    use kzg::{Kzg, KzgCommitment, trusted_setup::get_trusted_setup};
    use types::{
        BeaconBlock, BeaconBlockFulu, BlobsList, ChainSpec, EmptyBlock, EthSpec, ForkName,
        FullPayload, KzgProofs, MainnetEthSpec, SignedBeaconBlock,
        beacon_block_body::KzgCommitments,
    };

    type E = MainnetEthSpec;

    // Loading and initializing PeerDAS KZG is expensive and slow, so we group the tests together
    // only load it once.
    #[test]
    fn test_build_data_columns_sidecars() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let kzg = get_kzg();
        test_build_data_columns_empty(&kzg, &spec);
        test_build_data_columns(&kzg, &spec);
        test_reconstruct_data_columns(&kzg, &spec);
        test_reconstruct_data_columns_unordered(&kzg, &spec);
        test_reconstruct_blobs_from_data_columns(&kzg, &spec);
        test_validate_data_columns(&kzg, &spec);
    }

    #[track_caller]
    fn test_validate_data_columns(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 6;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();

        let result = validate_data_columns::<E, _>(kzg, column_sidecars.iter());
        assert!(result.is_ok());
    }

    #[track_caller]
    fn test_build_data_columns_empty(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 0;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();
        assert!(column_sidecars.is_empty());
    }

    #[track_caller]
    fn test_build_data_columns(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 6;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);

        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();

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

        assert_eq!(column_sidecars.len(), E::number_of_columns());
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
        let num_of_blobs = 2;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();

        // Now reconstruct
        let reconstructed_columns = reconstruct_data_columns(
            kzg,
            column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2].to_vec(),
            spec,
        )
        .unwrap();

        for i in 0..E::number_of_columns() {
            assert_eq!(reconstructed_columns.get(i), column_sidecars.get(i), "{i}");
        }
    }

    #[track_caller]
    fn test_reconstruct_data_columns_unordered(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 2;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();

        // Test reconstruction with columns in reverse order (non-ascending)
        let mut subset_columns: Vec<_> =
            column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2].to_vec();
        subset_columns.reverse(); // This would fail without proper sorting in reconstruct_data_columns
        let reconstructed_columns = reconstruct_data_columns(kzg, subset_columns, spec).unwrap();

        for i in 0..E::number_of_columns() {
            assert_eq!(reconstructed_columns.get(i), column_sidecars.get(i), "{i}");
        }
    }

    #[track_caller]
    fn test_reconstruct_blobs_from_data_columns(kzg: &Kzg, spec: &ChainSpec) {
        let num_of_blobs = 6;
        let (signed_block, blobs, proofs) =
            create_test_fulu_block_and_blobs::<E>(num_of_blobs, spec);
        let blob_refs = blobs.iter().collect::<Vec<_>>();
        let column_sidecars =
            blobs_to_data_column_sidecars(&blob_refs, proofs.to_vec(), &signed_block, kzg, spec)
                .unwrap();

        // Now reconstruct
        let signed_blinded_block = signed_block.into();
        let blob_indices = vec![3, 4, 5];
        let reconstructed_blobs = reconstruct_blobs(
            kzg,
            &column_sidecars.iter().as_slice()[0..column_sidecars.len() / 2],
            Some(blob_indices.clone()),
            &signed_blinded_block,
            spec,
        )
        .unwrap();

        for i in blob_indices {
            let reconstructed_blob = &reconstructed_blobs
                .iter()
                .find(|sidecar| sidecar.index == i)
                .map(|sidecar| sidecar.blob.clone())
                .expect("reconstructed blob should exist");
            let original_blob = blobs.get(i as usize).unwrap();
            assert_eq!(reconstructed_blob, original_blob, "{i}");
        }
    }

    fn get_kzg() -> Kzg {
        Kzg::new_from_trusted_setup(&get_trusted_setup()).expect("should create kzg")
    }

    fn create_test_fulu_block_and_blobs<E: EthSpec>(
        num_of_blobs: usize,
        spec: &ChainSpec,
    ) -> (
        SignedBeaconBlock<E, FullPayload<E>>,
        BlobsList<E>,
        KzgProofs<E>,
    ) {
        let mut block = BeaconBlock::Fulu(BeaconBlockFulu::empty(spec));
        let mut body = block.body_mut();
        let blob_kzg_commitments = body.blob_kzg_commitments_mut().unwrap();
        *blob_kzg_commitments =
            KzgCommitments::<E>::new(vec![KzgCommitment::empty_for_testing(); num_of_blobs])
                .unwrap();

        let mut signed_block = SignedBeaconBlock::from_block(block, Signature::empty());
        let fork = signed_block.fork_name_unchecked();
        let (blobs_bundle, _) = generate_blobs::<E>(num_of_blobs, fork).unwrap();
        let BlobsBundle {
            blobs,
            commitments,
            proofs,
        } = blobs_bundle;

        *signed_block
            .message_mut()
            .body_mut()
            .blob_kzg_commitments_mut()
            .unwrap() = commitments;

        (signed_block, blobs, proofs)
    }
}
