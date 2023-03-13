use crate::common::genesis_deposits;
use ethereum_hashing::hash;
use rayon::prelude::*;
use ssz::Encode;
use state_processing::initialize_beacon_state_from_eth1;
use types::{
    BeaconState, ChainSpec, DepositData, EthSpec, ExecutionPayloadHeader, Hash256, Keypair,
    PublicKey, Signature,
};

pub const DEFAULT_ETH1_BLOCK_HASH: &[u8] = &[0x42; 32];

pub fn bls_withdrawal_credentials(pubkey: &PublicKey, spec: &ChainSpec) -> Hash256 {
    let mut credentials = hash(&pubkey.as_ssz_bytes());
    credentials[0] = spec.bls_withdrawal_prefix_byte;
    Hash256::from_slice(&credentials)
}

fn eth1_withdrawal_credentials(pubkey: &PublicKey, spec: &ChainSpec) -> Hash256 {
    let fake_execution_address = &hash(&pubkey.as_ssz_bytes())[0..20];
    let mut credentials = [0u8; 32];
    credentials[0] = spec.eth1_address_withdrawal_prefix_byte;
    credentials[12..].copy_from_slice(fake_execution_address);
    Hash256::from_slice(&credentials)
}

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
    let withdrawal_credentials = keypairs
        .iter()
        .map(|keypair| bls_withdrawal_credentials(&keypair.pk, spec))
        .collect::<Vec<_>>();
    interop_genesis_state_with_withdrawal_credentials::<T>(
        keypairs,
        &withdrawal_credentials,
        genesis_time,
        eth1_block_hash,
        execution_payload_header,
        spec,
    )
}

// returns an interop genesis state except every other
// validator has eth1 withdrawal credentials
pub fn interop_genesis_state_with_eth1<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let withdrawal_credentials = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            if index % 2 == 0 {
                bls_withdrawal_credentials(&keypair.pk, spec)
            } else {
                eth1_withdrawal_credentials(&keypair.pk, spec)
            }
        })
        .collect::<Vec<_>>();
    interop_genesis_state_with_withdrawal_credentials::<T>(
        keypairs,
        &withdrawal_credentials,
        genesis_time,
        eth1_block_hash,
        execution_payload_header,
        spec,
    )
}

pub fn interop_genesis_state_with_withdrawal_credentials<T: EthSpec>(
    keypairs: &[Keypair],
    withdrawal_credentials: &[Hash256],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    if keypairs.len() != withdrawal_credentials.len() {
        return Err(format!(
            "wrong number of withdrawal credentials, expected: {}, got: {}",
            keypairs.len(),
            withdrawal_credentials.len()
        ));
    }

    let eth1_timestamp = 2_u64.pow(40);
    let amount = spec.max_effective_balance;

    let datas = keypairs
        .into_par_iter()
        .zip(withdrawal_credentials.into_par_iter())
        .map(|(keypair, &withdrawal_credentials)| {
            let mut data = DepositData {
                withdrawal_credentials,
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

    #[test]
    fn interop_state_with_eth1() {
        let validator_count = 16;
        let genesis_time = 42;
        let spec = &TestEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(validator_count);

        let state = interop_genesis_state_with_eth1::<TestEthSpec>(
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

        for (index, v) in state.validators().iter().enumerate() {
            let creds = v.withdrawal_credentials.as_bytes();
            if index % 2 == 0 {
                assert_eq!(
                    creds[0], spec.bls_withdrawal_prefix_byte,
                    "first byte of withdrawal creds should be bls prefix"
                );
                assert_eq!(
                    &creds[1..],
                    &hash(&v.pubkey.as_ssz_bytes())[1..],
                    "rest of withdrawal creds should be pubkey hash"
                );
            } else {
                assert_eq!(
                    creds[0], spec.eth1_address_withdrawal_prefix_byte,
                    "first byte of withdrawal creds should be eth1 prefix"
                );
                assert_eq!(
                    creds[1..12],
                    [0u8; 11],
                    "bytes [1:12] of withdrawal creds must be zero"
                );
                assert_eq!(
                    &creds[12..],
                    &hash(&v.pubkey.as_ssz_bytes())[0..20],
                    "rest of withdrawal creds should be first 20 bytes of pubkey hash"
                )
            }
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
