use crate::common::genesis_deposits;
use eth2_hashing::hash;
use rayon::prelude::*;
use ssz::Encode;
use state_processing::initialize_beacon_state_from_eth1;
use state_processing::{
    process_activations,
    upgrade::{upgrade_to_altair, upgrade_to_bellatrix},
};
use std::str::FromStr;
use types::{
    BeaconState, ChainSpec, DepositData, Eth1Data, EthSpec, ExecutionPayloadHeader, Hash256,
    Keypair, PublicKey, Signature, Validator,
};

pub const DEFAULT_ETH1_BLOCK_HASH: &[u8] = &[0x42; 32];

/// Builds a genesis state as defined by the Eth2 interop procedure (see below).
///
/// Reference:
/// https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start
pub fn interop_genesis_state<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let eth1_timestamp = 2_u64.pow(40);
    let amount = spec.max_effective_balance;

    let withdrawal_credentials = |pubkey: &PublicKey| {
        let mut credentials = hash(&pubkey.as_ssz_bytes());
        credentials[0] = spec.bls_withdrawal_prefix_byte;
        Hash256::from_slice(&credentials)
    };

    let datas = keypairs
        .into_par_iter()
        .map(|keypair| {
            let mut data = DepositData {
                withdrawal_credentials: withdrawal_credentials(&keypair.pk),
                pubkey: keypair.pk.clone().into(),
                amount,
                signature: Signature::empty().into(),
            };

            data.signature = data.create_signature(&keypair.sk, spec);

            data
        })
        .collect::<Vec<_>>();

    let mut state = initialize_beacon_state_from_eth1(
        eth1_block_hash,
        eth1_timestamp,
        genesis_deposits(datas, spec)?,
        execution_payload_header,
        spec,
    )
    .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

    *state.genesis_time_mut() = genesis_time;

    // Invalidate all the caches after all the manual state surgery.
    state
        .drop_all_caches()
        .map_err(|e| format!("Unable to drop caches: {:?}", e))?;

    Ok(state)
}

/// Initialize a BeaconState with the given validators activated.
/// This gives us the advantage of not requiring to perform deposits for
/// these set of validators.
///
/// TODO(pawan): improve docs
pub fn initialize_state_with_validators<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    // Empty eth1 data
    let eth1_data = Eth1Data {
        block_hash: eth1_block_hash,
        deposit_count: 0,
        deposit_root: Hash256::from_str(
            "0xd70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e",
        )
        .unwrap(), // empty deposit tree root
    };
    let mut state = BeaconState::new(genesis_time, eth1_data, spec);

    // Seed RANDAO with Eth1 entropy
    state.fill_randao_mixes_with(eth1_block_hash);

    for keypair in keypairs.into_iter() {
        let withdrawal_credentials = |pubkey: &PublicKey| {
            let mut credentials = hash(&pubkey.as_ssz_bytes());
            credentials[0] = spec.bls_withdrawal_prefix_byte;
            Hash256::from_slice(&credentials)
        };
        let amount = spec.max_effective_balance;
        // Create a new validator.
        let validator = Validator {
            pubkey: keypair.pk.clone().into(),
            withdrawal_credentials: withdrawal_credentials(&keypair.pk),
            activation_eligibility_epoch: spec.far_future_epoch,
            activation_epoch: spec.far_future_epoch,
            exit_epoch: spec.far_future_epoch,
            withdrawable_epoch: spec.far_future_epoch,
            effective_balance: std::cmp::min(
                amount - amount % (spec.effective_balance_increment),
                spec.max_effective_balance,
            ),
            slashed: false,
        };
        state.validators_mut().push(validator).unwrap();
        state.balances_mut().push(amount).unwrap();
    }

    process_activations(&mut state, spec).unwrap();

    if spec
        .altair_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == T::genesis_epoch())
    {
        upgrade_to_altair(&mut state, spec).unwrap();

        state.fork_mut().previous_version = spec.altair_fork_version;
    }

    // Similarly, perform an upgrade to the merge if configured from genesis.
    if spec
        .bellatrix_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == T::genesis_epoch())
    {
        upgrade_to_bellatrix(&mut state, spec).unwrap();

        // Remove intermediate Altair fork from `state.fork`.
        state.fork_mut().previous_version = spec.bellatrix_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/beacon-chain.md#testing
        *state.latest_execution_payload_header_mut().unwrap() =
            execution_payload_header.unwrap_or_default();
    }

    // Now that we have our validators, initialize the caches (including the committees)
    state.build_all_caches(spec).unwrap();

    // Set genesis validators root for domain separation and chain versioning
    *state.genesis_validators_root_mut() = state.update_validators_tree_hash_cache().unwrap();

    Ok(state)
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{test_utils::generate_deterministic_keypairs, EthSpec, MinimalEthSpec};

    type TestEthSpec = MinimalEthSpec;

    #[test]
    fn interop_state() {
        let validator_count = 16;
        let genesis_time = 42;
        let spec = &TestEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(validator_count);

        let state = interop_genesis_state::<TestEthSpec>(
            &keypairs,
            genesis_time,
            Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
            None,
            spec,
        )
        .expect("should build state");

        assert_eq!(
            state.eth1_data().block_hash,
            Hash256::from_slice(&[0x42; 32]),
            "eth1 block hash should be co-ordinated junk"
        );

        assert_eq!(
            state.genesis_time(),
            genesis_time,
            "genesis time should be as specified"
        );

        for b in state.balances() {
            assert_eq!(
                *b, spec.max_effective_balance,
                "validator balances should be max effective balance"
            );
        }

        for v in state.validators() {
            let creds = v.withdrawal_credentials.as_bytes();
            assert_eq!(
                creds[0], spec.bls_withdrawal_prefix_byte,
                "first byte of withdrawal creds should be bls prefix"
            );
            assert_eq!(
                &creds[1..],
                &hash(&v.pubkey.as_ssz_bytes())[1..],
                "rest of withdrawal creds should be pubkey hash"
            )
        }

        assert_eq!(
            state.balances().len(),
            validator_count,
            "validator balances len should be correct"
        );

        assert_eq!(
            state.validators().len(),
            validator_count,
            "validator count should be correct"
        );
    }
}
