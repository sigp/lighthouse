use super::errors::{DepositInvalid as Invalid, DepositValidationError as Error};
use merkle_proof::verify_merkle_proof;
use std::convert::TryInto;
use tree_hash::{SignedRoot, TreeHash};
use types::*;

/// Verify `Deposit.pubkey` signed `Deposit.signature`.
///
/// Spec v0.8.0
pub fn verify_deposit_signature<T: EthSpec>(
    state: &BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
    pubkey: &PublicKey,
) -> Result<(), Error> {
    // Note: Deposits are valid across forks, thus the deposit domain is computed
    // with the fork zeroed.
    let domain = spec.get_domain(state.current_epoch(), Domain::Deposit, &Fork::default());
    let signature: Signature = (&deposit.data.signature)
        .try_into()
        .map_err(|_| Error::Invalid(Invalid::BadSignatureBytes))?;

    verify!(
        signature.verify(&deposit.data.signed_root(), domain, pubkey),
        Invalid::BadSignature
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
) -> Result<Option<u64>, Error> {
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
) -> Result<(), Error> {
    let leaf = deposit.data.tree_hash_root();

    verify!(
        verify_merkle_proof(
            Hash256::from_slice(&leaf),
            &deposit.proof[..],
            spec.deposit_contract_tree_depth as usize + 1,
            deposit_index as usize,
            state.eth1_data.deposit_root,
        ),
        Invalid::BadMerkleProof
    );

    Ok(())
}
