use db::{
    ClientDB,
};
use db::stores::{
    BeaconBlockStore,
    PoWChainStore,
    ValidatorStore,
};
use std::sync::Arc;

pub struct BeaconChainStore<T: ClientDB + Sized> {
    pub block: Arc<BeaconBlockStore<T>>,
    pub pow_chain: Arc<PoWChainStore<T>>,
    pub validator: Arc<ValidatorStore<T>>,
}
