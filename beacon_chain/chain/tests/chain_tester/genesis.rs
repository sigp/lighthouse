use super::ChainTester;
use bls::{create_proof_of_possession, Keypair};
use chain::{BeaconChain, BeaconChainError, BeaconChainStore};
use db::stores::{BeaconBlockStore, PoWChainStore, ValidatorStore};
use db::ClientDB;
use std::sync::Arc;
use types::{Address, ChainConfig, Hash256, ValidatorRegistration};

impl<T: ClientDB> ChainTester<T> {
    pub fn genesis(
        db: Arc<T>,
        config: ChainConfig,
        validator_count: usize,
    ) -> Result<Self, BeaconChainError> {
        let mut validator_keypairs = vec![];
        let mut validator_registrations = vec![];
        for _ in 0..validator_count {
            let keypair = Keypair::random();
            let validator_registration = ValidatorRegistration {
                pubkey: keypair.pk.clone(),
                withdrawal_shard: 0,
                withdrawal_address: Address::zero(),
                randao_commitment: Hash256::zero(),
                proof_of_possession: create_proof_of_possession(&keypair),
            };
            validator_keypairs.push(keypair);
            validator_registrations.push(validator_registration);
        }

        let store = BeaconChainStore {
            block: Arc::new(BeaconBlockStore::new(db.clone())),
            pow_chain: Arc::new(PoWChainStore::new(db.clone())),
            validator: Arc::new(ValidatorStore::new(db.clone())),
        };

        let chain = BeaconChain::new(store, config)?;

        Ok(Self {
            db,
            chain,
            validator_keypairs,
        })
    }
}
