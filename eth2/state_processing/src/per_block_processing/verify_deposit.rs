use super::errors::{BlockOperationError, DepositInvalid};
use crate::per_block_processing::signature_sets::{
    deposit_pubkey_signature_message, deposit_signature_set,
};
use merkle_proof::verify_merkle_proof;
use tree_hash::TreeHash;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<DepositInvalid>>;

fn error(reason: DepositInvalid) -> BlockOperationError<DepositInvalid> {
    BlockOperationError::invalid(reason)
}

/// Verify `Deposit.pubkey` signed `Deposit.signature`.
///
/// Spec v0.8.0
pub fn verify_deposit_signature<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> Result<()> {
    let deposit_signature_message = deposit_pubkey_signature_message(deposit)
        .ok_or_else(|| error(DepositInvalid::BadBlsBytes))?;

    verify!(
        deposit_signature_set(state, &deposit_signature_message, spec).is_valid(),
        DepositInvalid::BadSignature
    );

    Ok(())
}

/// Returns a `Some(validator index)` if a pubkey already exists in the `validators`,
/// otherwise returns `None`.
///
/// ## Errors
///
/// Errors if the state's `pubkey_cache` is not current.
pub fn get_existing_validator_index<T: EthSpec>(
    state: &BeaconState<T>,
    pub_key: &PublicKey,
) -> Result<Option<u64>> {
    let validator_index = state.get_validator_index(pub_key)?;
    Ok(validator_index.map(|idx| idx as u64))
}

/// Verify that a deposit is included in the state's eth1 deposit root.
///
/// The deposit index is provided as a parameter so we can check proofs
/// before they're due to be processed, and in parallel.
///
/// Spec v0.8.0
pub fn verify_deposit_merkle_proof<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    deposit_index: u64,
    spec: &ChainSpec,
) -> Result<()> {
    let leaf = deposit.data.tree_hash_root();

    verify!(
        verify_merkle_proof(
            Hash256::from_slice(&leaf),
            &deposit.proof[..],
            spec.deposit_contract_tree_depth as usize + 1,
            deposit_index as usize,
            state.eth1_data.deposit_root,
        ),
        DepositInvalid::BadMerkleProof
    );

    Ok(())
}
