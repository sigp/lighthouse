use std::sync::Arc;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use types::{light_client_bootstrap::LightClientBootstrap, EthSpec, Hash256};

use crate::Error;

pub async fn get_light_client_bootstrap<T: BeaconChainTypes, E: EthSpec>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
) -> Result<LightClientBootstrap<T::EthSpec>, Error> {
    let Some(block) = chain.get_block(&block_root).await.unwrap() else {
        panic!();
    };

    let Some(mut state) = chain
        .get_state(&block.state_root(), Some(block.slot()))
        .unwrap()
    else {
        panic!();
    };

    Ok(LightClientBootstrap::create_light_client_bootstrap(&mut state, block).unwrap())
}
