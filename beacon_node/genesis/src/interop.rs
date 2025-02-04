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

pub type WithdrawalCredentialsFn =
    Box<dyn for<'a> Fn(usize, &'a PublicKey, &'a ChainSpec) -> Hash256>;

/// Builds a genesis state as defined by the Eth2 interop procedure (see below).
///
/// Reference:
/// https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start
#[derive(Default)]
pub struct InteropGenesisBuilder<E: EthSpec> {
    /// Mapping from validator index to initial balance for each validator.
    ///
    /// If `None`, then the default balance of 32 ETH will be used.
    initial_balance_fn: Option<Box<dyn Fn(usize) -> u64>>,

    /// Mapping from validator index and pubkey to withdrawal credentials for each validator.
    ///
    /// If `None`, then default BLS withdrawal credentials will be used.
    withdrawal_credentials_fn: Option<WithdrawalCredentialsFn>,

    /// The execution payload header to embed in the genesis state.
    execution_payload_header: Option<ExecutionPayloadHeader<E>>,
}

impl<E: EthSpec> InteropGenesisBuilder<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_initial_balance_fn(mut self, initial_balance_fn: Box<dyn Fn(usize) -> u64>) -> Self {
        self.initial_balance_fn = Some(initial_balance_fn);
        self
    }

    pub fn set_withdrawal_credentials_fn(
        mut self,
        withdrawal_credentials_fn: WithdrawalCredentialsFn,
    ) -> Self {
        self.withdrawal_credentials_fn = Some(withdrawal_credentials_fn);
        self
    }

    pub fn set_alternating_eth1_withdrawal_credentials(self) -> Self {
        self.set_withdrawal_credentials_fn(Box::new(alternating_eth1_withdrawal_credentials_fn))
    }

    pub fn set_execution_payload_header(
        self,
        execution_payload_header: ExecutionPayloadHeader<E>,
    ) -> Self {
        self.set_opt_execution_payload_header(Some(execution_payload_header))
    }

    pub fn set_opt_execution_payload_header(
        mut self,
        execution_payload_header: Option<ExecutionPayloadHeader<E>>,
    ) -> Self {
        self.execution_payload_header = execution_payload_header;
        self
    }

    pub fn build_genesis_state(
        self,
        keypairs: &[Keypair],
        genesis_time: u64,
        eth1_block_hash: Hash256,
        spec: &ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        // Generate withdrawal credentials using provided function, or default BLS.
        let withdrawal_credentials_fn = self.withdrawal_credentials_fn.unwrap_or_else(|| {
            Box::new(|_, pubkey, spec| bls_withdrawal_credentials(pubkey, spec))
        });

        let withdrawal_credentials = keypairs
            .iter()
            .map(|key| &key.pk)
            .enumerate()
            .map(|(i, pubkey)| withdrawal_credentials_fn(i, pubkey, spec))
            .collect::<Vec<_>>();

        // Generate initial balances.
        let initial_balance_fn = self
            .initial_balance_fn
            .unwrap_or_else(|| Box::new(|_| spec.max_effective_balance));

        let eth1_timestamp = 2_u64.pow(40);

        let initial_balances = (0..keypairs.len())
            .map(initial_balance_fn)
            .collect::<Vec<_>>();

        let datas = keypairs
            .into_par_iter()
            .zip(withdrawal_credentials.into_par_iter())
            .zip(initial_balances.into_par_iter())
            .map(|((keypair, withdrawal_credentials), amount)| {
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
            self.execution_payload_header,
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
}

pub fn interop_genesis_state<E: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<E>>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    InteropGenesisBuilder::new()
        .set_opt_execution_payload_header(execution_payload_header)
        .build_genesis_state(keypairs, genesis_time, eth1_block_hash, spec)
}

fn alternating_eth1_withdrawal_credentials_fn<'a>(
    index: usize,
    pubkey: &'a PublicKey,
    spec: &'a ChainSpec,
) -> Hash256 {
    if index % 2usize == 0usize {
        bls_withdrawal_credentials(pubkey, spec)
    } else {
        eth1_withdrawal_credentials(pubkey, spec)
    }
}

// returns an interop genesis state except every other
// validator has eth1 withdrawal credentials
pub fn interop_genesis_state_with_eth1<E: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<E>>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    InteropGenesisBuilder::new()
        .set_alternating_eth1_withdrawal_credentials()
        .set_opt_execution_payload_header(execution_payload_header)
        .build_genesis_state(keypairs, genesis_time, eth1_block_hash, spec)
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{test_utils::generate_deterministic_keypairs, MinimalEthSpec};

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
            let creds = v.withdrawal_credentials;
            assert_eq!(
                creds.as_slice()[0],
                spec.bls_withdrawal_prefix_byte,
                "first byte of withdrawal creds should be bls prefix"
            );
            assert_eq!(
                &creds.as_slice()[1..],
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
            let withdrawal_credientials = v.withdrawal_credentials;
            let creds = withdrawal_credientials.as_slice();
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
