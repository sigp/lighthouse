#[cfg(test)]
mod tests {
    use crate::{
        beacon_state::BeaconStateError, BeaconState, ChainSpec, Deposit, DepositData, DepositInput,
        Eth1Data, Hash256, Keypair,
    };
    use bls::create_proof_of_possession;

    struct BeaconStateTestBuilder {
        pub genesis_time: u64,
        pub initial_validator_deposits: Vec<Deposit>,
        pub latest_eth1_data: Eth1Data,
        pub spec: ChainSpec,
        pub keypairs: Vec<Keypair>,
    }

    impl BeaconStateTestBuilder {
        pub fn with_random_validators(validator_count: usize) -> Self {
            let genesis_time = 10_000_000;
            let keypairs: Vec<Keypair> = (0..validator_count)
                .collect::<Vec<usize>>()
                .iter()
                .map(|_| Keypair::random())
                .collect();
            let initial_validator_deposits = keypairs
                .iter()
                .map(|keypair| Deposit {
                    branch: vec![], // branch verification is not specified.
                    index: 0,       // index verification is not specified.
                    deposit_data: DepositData {
                        amount: 32_000_000_000, // 32 ETH (in Gwei)
                        timestamp: genesis_time - 1,
                        deposit_input: DepositInput {
                            pubkey: keypair.pk.clone(),
                            withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                            proof_of_possession: create_proof_of_possession(&keypair),
                        },
                    },
                })
                .collect();
            let latest_eth1_data = Eth1Data {
                deposit_root: Hash256::zero(),
                block_hash: Hash256::zero(),
            };
            let spec = ChainSpec::foundation();

            Self {
                genesis_time,
                initial_validator_deposits,
                latest_eth1_data,
                spec,
                keypairs,
            }
        }

        pub fn build(&self) -> Result<BeaconState, BeaconStateError> {
            BeaconState::genesis(
                self.genesis_time,
                self.initial_validator_deposits.clone(),
                self.latest_eth1_data.clone(),
                &self.spec,
            )
        }
    }

    #[test]
    pub fn can_produce_genesis_block() {
        let builder = BeaconStateTestBuilder::with_random_validators(2);

        builder.build().unwrap();
    }
}
