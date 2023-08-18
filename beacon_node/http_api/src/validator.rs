use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use types::*;

/// Uses the `chain.validator_pubkey_cache` to resolve a pubkey to a validator
/// index and then ensures that the validator exists in the given `state`.
pub fn pubkey_to_validator_index<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    pubkey: &PublicKeyBytes,
) -> Result<Option<usize>, BeaconChainError> {
    chain
        .validator_index(pubkey)?
        .filter(|&index| {
            state
                .validators()
                .get(index)
                .map_or(false, |v| v.pubkey == *pubkey)
        })
        .map(Result::Ok)
        .transpose()
}
