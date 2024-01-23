use crate::local_network::EXECUTION_PORT;
use crate::LocalNetwork;
use eth1::{Eth1Endpoint, DEFAULT_CHAIN_ID};
use eth1_test_rig::AnvilEth1Instance;

use execution_layer::http::deposit_methods::Eth1Id;
use node_test_rig::environment::RuntimeContext;
use node_test_rig::{testing_client_config, ClientConfig, ClientGenesis};
use sensitive_url::SensitiveUrl;
use std::net::Ipv4Addr;
use std::time::Duration;
use types::EthSpec;

pub struct LocalNetworkParams {
    pub eth1_block_time: Duration,
    pub total_validator_count: usize,
    pub deposit_amount: u64,
    pub node_count: usize,
    pub proposer_nodes: usize,
    pub post_merge_sim: bool,
}

pub async fn create_local_network<E: EthSpec>(
    LocalNetworkParams {
        eth1_block_time,
        total_validator_count,
        deposit_amount,
        node_count,
        proposer_nodes,
        post_merge_sim,
    }: LocalNetworkParams,
    context: RuntimeContext<E>,
) -> Result<(LocalNetwork<E>, ClientConfig), String> {
    /*
     * Deploy the deposit contract, spawn tasks to keep creating new blocks and deposit
     * validators.
     */
    let anvil_eth1_instance = AnvilEth1Instance::new(DEFAULT_CHAIN_ID.into()).await?;
    let deposit_contract = anvil_eth1_instance.deposit_contract;
    let chain_id = anvil_eth1_instance.anvil.chain_id();
    let anvil = anvil_eth1_instance.anvil;
    let eth1_endpoint =
        SensitiveUrl::parse(anvil.endpoint().as_str()).expect("Unable to parse anvil endpoint.");
    let deposit_contract_address = deposit_contract.address();

    // Start a timer that produces eth1 blocks on an interval.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(eth1_block_time);
        loop {
            interval.tick().await;
            let _ = anvil.evm_mine().await;
        }
    });

    // Submit deposits to the deposit contract.
    tokio::spawn(async move {
        for i in 0..total_validator_count {
            println!("Submitting deposit for validator {}...", i);
            let _ = deposit_contract
                .deposit_deterministic_async::<E>(i, deposit_amount)
                .await;
        }
    });

    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::DepositContract;
    beacon_config.eth1.endpoint = Eth1Endpoint::NoAuth(eth1_endpoint);
    beacon_config.eth1.deposit_contract_address = deposit_contract_address;
    beacon_config.eth1.deposit_contract_deploy_block = 0;
    beacon_config.eth1.lowest_cached_block_number = 0;
    beacon_config.eth1.follow_distance = 1;
    beacon_config.eth1.node_far_behind_seconds = 20;
    beacon_config.dummy_eth1_backend = false;
    beacon_config.sync_eth1_chain = true;
    beacon_config.eth1.auto_update_interval_millis = eth1_block_time.as_millis() as u64;
    beacon_config.eth1.chain_id = Eth1Id::from(chain_id);
    beacon_config.network.target_peers = node_count + proposer_nodes - 1;

    beacon_config.network.enr_address = (Some(Ipv4Addr::LOCALHOST), None);

    if post_merge_sim {
        let el_config = execution_layer::Config {
            execution_endpoints: vec![SensitiveUrl::parse(&format!(
                "http://localhost:{}",
                EXECUTION_PORT
            ))
            .unwrap()],
            ..Default::default()
        };

        beacon_config.execution_layer = Some(el_config);
    }

    let network = LocalNetwork::new(context, beacon_config.clone()).await?;
    Ok((network, beacon_config))
}
