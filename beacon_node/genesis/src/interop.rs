use crate::common::genesis_deposits;
use eth2_hashing::hash;
use rayon::prelude::*;
use ssz::Encode;
use state_processing::initialize_beacon_state_from_eth1;
use types::{BeaconState, ChainSpec, DepositData, EthSpec, Hash256, Keypair, PublicKey, Signature};

/// Builds a genesis state as defined by the Eth2 interop procedure (see below).
///
/// Reference:
/// https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start
pub fn interop_genesis_state<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let eth1_block_hash = Hash256::from_slice(&[0x42; 32]);
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

        let state = interop_genesis_state::<TestEthSpec>(&keypairs, genesis_time, spec)
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
