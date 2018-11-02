use db::ClientDB;
use std::sync::Arc;
use chain::BeaconChain;
use bls::Keypair;

mod block;
mod genesis;

pub struct ChainTester<T: ClientDB> {
    pub db: Arc<T>,
    pub chain: BeaconChain<T>,
    pub validator_keypairs: Vec<Keypair>,
}
