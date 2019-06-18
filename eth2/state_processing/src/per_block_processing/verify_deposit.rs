use super::errors::{DepositInvalid as Invalid, DepositValidationError as Error};
use merkle_proof::verify_merkle_proof;
use tree_hash::{SignedRoot, TreeHash};
use types::*;

/// Verify `Deposit.pubkey` signed `Deposit.signature`.
///
/// Spec v0.6.3
pub fn verify_deposit_signature<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        deposit.data.signature.verify(
            &deposit.data.signed_root(),
            spec.get_domain(state.current_epoch(), Domain::Deposit, &state.fork),
            &deposit.data.pubkey,
        ),
        Invalid::BadSignature
    );

    Ok(())
}

/// Verify that the `Deposit` index is correct.
///
/// Spec v0.6.3
pub fn verify_deposit_index<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
) -> Result<(), Error> {
    verify!(
        deposit.index == state.deposit_index,
        Invalid::BadIndex {
            state: state.deposit_index,
            deposit: deposit.index
        }
    );

    Ok(())
}

/// Returns a `Some(validator index)` if a pubkey already exists in the `validator_registry`,
/// otherwise returns `None`.
///
/// ## Errors
///
/// Errors if the state's `pubkey_cache` is not current.
pub fn get_existing_validator_index<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
) -> Result<Option<u64>, Error> {
    let validator_index = state.get_validator_index(&deposit.data.pubkey)?;
    Ok(validator_index.map(|idx| idx as u64))
}

/// Verify that a deposit is included in the state's eth1 deposit root.
///
/// Spec v0.6.3
pub fn verify_deposit_merkle_proof<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let leaf = deposit.data.tree_hash_root();

    verify!(
        verify_merkle_proof(
            Hash256::from_slice(&leaf),
            &deposit.proof[..],
            spec.deposit_contract_tree_depth as usize,
            deposit.index as usize,
            state.latest_eth1_data.deposit_root,
        ),
        Invalid::BadMerkleProof
    );

    Ok(())
}
