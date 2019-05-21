use super::errors::{DepositInvalid as Invalid, DepositValidationError as Error};
use hashing::hash;
use merkle_proof::verify_merkle_proof;
use ssz::ssz_encode;
use ssz_derive::Encode;
use tree_hash::{SignedRoot, TreeHash};
use types::*;

/// Indicates if a `Deposit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Deposit` is valid, otherwise indicates the reason for invalidity.
///
/// This function _does not_ check `state.deposit_index` so this function may be run in parallel.
/// See the `verify_deposit_index` function for this.
///
/// Note: this function is incomplete.
///
/// Spec v0.6.1
pub fn verify_deposit<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    verify_merkle_branch: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if verify_merkle_branch {
        verify!(
            verify_deposit_merkle_proof(state, deposit, spec),
            Invalid::BadMerkleProof
        );
    }

    // NOTE: proof of possession should only be verified when the validator
    // is not already part of the registry
    verify!(
        deposit.data.signature.verify(
            &deposit.data.signed_root(),
            spec.get_domain(state.current_epoch(), Domain::Deposit, &state.fork),
            &deposit.data.pubkey,
        ),
        Invalid::BadProofOfPossession
    );

    Ok(())
}

/// Verify that the `Deposit` index is correct.
///
/// Spec v0.6.1
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

    // NOTE: it seems that v0.6.1 doesn't require the withdrawal credentials to be checked
    match validator_index {
        None => Ok(None),
        Some(index) => {
            verify!(
                deposit.data.withdrawal_credentials
                    == state.validator_registry[index].withdrawal_credentials,
                Invalid::BadWithdrawalCredentials
            );
            Ok(Some(index as u64))
        }
    }
}

/// Verify that a deposit is included in the state's eth1 deposit root.
///
/// Spec v0.6.1
fn verify_deposit_merkle_proof<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> bool {
    let leaf = deposit.data.tree_hash_root();
    verify_merkle_proof(
        Hash256::from_slice(&leaf),
        &deposit.proof[..],
        spec.deposit_contract_tree_depth as usize,
        deposit.index as usize,
        state.latest_eth1_data.deposit_root,
    )
}
