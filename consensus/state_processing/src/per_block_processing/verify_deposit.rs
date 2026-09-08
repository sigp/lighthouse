use super::errors::{BlockOperationError, DepositInvalid};
use crate::per_block_processing::signature_sets::deposit_pubkey_signature_message;
use bls::{PublicKey, PublicKeyBytes, Signature, SignatureSet, verify_signature_sets};
use merkle_proof::verify_merkle_proof;
use rayon::prelude::*;
use safe_arith::SafeArith;
use std::borrow::Cow;
use tracing::instrument;
use tree_hash::TreeHash;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<DepositInvalid>>;

const DEPOSIT_SIGNATURE_BATCH_SIZE: usize = 8;

fn error(reason: DepositInvalid) -> BlockOperationError<DepositInvalid> {
    BlockOperationError::invalid(reason)
}

/// Verify `Deposit.pubkey` signed `Deposit.signature`.
///
/// Spec v0.12.1
pub fn is_valid_deposit_signature(deposit_data: &DepositData, spec: &ChainSpec) -> Result<()> {
    let (public_key, signature, msg) = deposit_pubkey_signature_message(deposit_data, spec)
        .ok_or_else(|| error(DepositInvalid::BadBlsBytes))?;

    verify!(
        signature.verify(&public_key, msg),
        DepositInvalid::BadSignature
    );

    Ok(())
}

/// Returns a `Some(validator index)` if a pubkey already exists in the `validators`,
/// otherwise returns `None`.
///
/// Builds the pubkey cache if it is not already built.
pub fn get_existing_validator_index<E: EthSpec>(
    state: &mut BeaconState<E>,
    pub_key: &PublicKeyBytes,
) -> Result<Option<u64>> {
    let validator_index = state.get_validator_index(pub_key)?;
    Ok(validator_index.map(|idx| idx as u64))
}

/// Verify that a deposit is included in the state's eth1 deposit root.
///
/// The deposit index is provided as a parameter so we can check proofs
/// before they're due to be processed, and in parallel.
///
/// Spec v0.12.1
pub fn verify_deposit_merkle_proof<E: EthSpec>(
    state: &BeaconState<E>,
    deposit: &Deposit,
    deposit_index: u64,
    spec: &ChainSpec,
) -> Result<()> {
    let leaf = deposit.data.tree_hash_root();

    verify!(
        verify_merkle_proof(
            leaf,
            &deposit.proof[..],
            spec.deposit_contract_tree_depth.safe_add(1)? as usize,
            deposit_index as usize,
            state.eth1_data().deposit_root,
        ),
        DepositInvalid::BadMerkleProof
    );

    Ok(())
}

/// Batch verify a slice of deposit signatures.
fn verify_deposit_signature_sets(entries: &[&(usize, PublicKey, Signature, Hash256)]) -> bool {
    if entries.is_empty() {
        return true;
    }

    let signature_sets = entries
        .iter()
        .map(|(_, public_key, signature, message)| {
            SignatureSet::single_pubkey(signature, Cow::Borrowed(public_key), *message)
        })
        .collect::<Vec<_>>();

    verify_signature_sets(signature_sets.iter())
}

/// Helper for verifying a single deposit signature.
fn verify_deposit_signature(entry: &(usize, PublicKey, Signature, Hash256)) -> bool {
    let (_, public_key, signature, message) = entry;
    signature.verify(public_key, *message)
}

/// Verify `Deposit.pubkey` signed `Deposit.signature` for each deposit in batches of
/// `DEPOSIT_SIGNATURE_BATCH_SIZE`.
///
/// Returns `true` for valid signatures and `false` for invalid signatures.
///
/// Note: decompression failures are also considered as invalid signatures.
#[instrument(skip_all, level = "debug")]
pub fn is_valid_deposit_signature_batch(
    deposit_data: Vec<DepositData>,
    spec: &ChainSpec,
) -> Vec<bool> {
    let decompressed = deposit_data
        .par_iter()
        .enumerate()
        .map(|(index, deposit)| {
            deposit_pubkey_signature_message(deposit, spec)
                .map(|(public_key, signature, message)| (index, public_key, signature, message))
        })
        .collect::<Vec<_>>();

    // Initialize with false to ensure signatures that fail decompression above are also
    // marked as signature verification failures.
    let mut results = vec![false; decompressed.len()];

    let batch_results = decompressed
        .par_chunks(DEPOSIT_SIGNATURE_BATCH_SIZE)
        .map(|chunk| {
            let valid_entries = chunk
                .iter()
                .filter_map(|entry| entry.as_ref())
                .collect::<Vec<_>>();

            // All signatures in this batch are valid.
            if verify_deposit_signature_sets(&valid_entries) {
                valid_entries
                    .into_iter()
                    .map(|entry| (entry.0, true))
                    .collect::<Vec<_>>()
            // There were some invalid signatures in this batch,
            // verify individually to detect the invalid signatures.
            } else {
                valid_entries
                    .into_iter()
                    .map(|entry| (entry.0, verify_deposit_signature(entry)))
                    .collect::<Vec<_>>()
            }
        })
        .collect::<Vec<_>>();

    for (index, is_valid) in batch_results.into_iter().flatten() {
        debug_assert!(index < results.len());
        if let Some(res) = results.get_mut(index) {
            *res = is_valid;
        }
    }

    results
}
