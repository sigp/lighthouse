use deposit_contract::DEPOSIT_GAS;
use environment::Environment;
use futures::{
    compat::Future01CompatExt,
    stream::{FuturesUnordered, StreamExt},
};
use slog::{info, Logger};
use state_processing::per_block_processing::verify_deposit_signature;
use tokio::time::{delay_until, Duration, Instant};
use types::EthSpec;
use validator_dir::{Eth1DepositData, ValidatorDir};
use web3::{
    types::{Address, SyncInfo, SyncState, TransactionRequest, U256},
    Transport, Web3,
};

const SYNCING_STATE_RETRY_DELAY: Duration = Duration::from_secs(2);

const CONFIRMATIONS_POLL_TIME: Duration = Duration::from_secs(2);

#[allow(clippy::too_many_arguments)]
pub fn send_deposit_transactions<T1, T2: 'static>(
    mut env: Environment<T1>,
    log: Logger,
    mut eth1_deposit_datas: Vec<(ValidatorDir, Eth1DepositData)>,
    from_address: Address,
    deposit_contract: Address,
    transport: T2,
    confirmation_count: usize,
    confirmation_batch_size: usize,
    save_tx_hash: bool,
) -> Result<(), String>
where
    T1: EthSpec,
    T2: Transport + std::marker::Send,
    <T2 as web3::Transport>::Out: std::marker::Send,
{
    let web3 = Web3::new(transport);
    let spec = env.eth2_config.spec.clone();

    let deposits_fut = async {
        poll_until_synced(web3.clone(), log.clone()).await?;

        for chunk in eth1_deposit_datas.chunks_mut(confirmation_batch_size) {
            let futures = FuturesUnordered::default();

            for (ref mut validator_dir, eth1_deposit_data) in chunk.iter_mut() {
                verify_deposit_signature(&eth1_deposit_data.deposit_data, &spec).map_err(|e| {
                    format!(
                        "Deposit for {:?} fails verification, \
                         are you using the correct testnet configuration?\nError: {:?}",
                        eth1_deposit_data.deposit_data.pubkey, e
                    )
                })?;

                let web3 = web3.clone();
                let log = log.clone();
                futures.push(async move {
                    let tx_hash = web3
                        .send_transaction_with_confirmation(
                            TransactionRequest {
                                from: from_address,
                                to: Some(deposit_contract),
                                gas: Some(DEPOSIT_GAS.into()),
                                gas_price: None,
                                value: Some(from_gwei(eth1_deposit_data.deposit_data.amount)),
                                data: Some(eth1_deposit_data.rlp.clone().into()),
                                nonce: None,
                                condition: None,
                            },
                            CONFIRMATIONS_POLL_TIME,
                            confirmation_count,
                        )
                        .compat()
                        .await
                        .map_err(|e| format!("Failed to send transaction: {:?}", e))?;

                    info!(
                        log,
                        "Submitted deposit";
                        "tx_hash" => format!("{:?}", tx_hash),
                    );

                    if save_tx_hash {
                        validator_dir
                            .save_eth1_deposit_tx_hash(&format!("{:?}", tx_hash))
                            .map_err(|e| {
                                format!("Failed to save tx hash {:?} to disk: {:?}", tx_hash, e)
                            })?;
                    }

                    Ok::<(), String>(())
                });
            }

            futures
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<_, _>>()?;
        }

        Ok::<(), String>(())
    };

    env.runtime().block_on(deposits_fut)?;

    Ok(())
}

/// Converts gwei to wei.
fn from_gwei(gwei: u64) -> U256 {
    U256::from(gwei) * U256::exp10(9)
}

/// Run a poll on the `eth_syncing` endpoint, blocking until the node is synced.
async fn poll_until_synced<T>(web3: Web3<T>, log: Logger) -> Result<(), String>
where
    T: Transport + Send + 'static,
    <T as Transport>::Out: Send,
{
    loop {
        let sync_state = web3
            .clone()
            .eth()
            .syncing()
            .compat()
            .await
            .map_err(|e| format!("Unable to read syncing state from eth1 node: {:?}", e))?;

        match sync_state {
            SyncState::Syncing(SyncInfo {
                current_block,
                highest_block,
                ..
            }) => {
                info!(
                    log,
                    "Waiting for eth1 node to sync";
                    "est_highest_block" => format!("{}", highest_block),
                    "current_block" => format!("{}", current_block),
                );

                delay_until(Instant::now() + SYNCING_STATE_RETRY_DELAY).await;
            }
            SyncState::NotSyncing => {
                let block_number = web3
                    .clone()
                    .eth()
                    .block_number()
                    .compat()
                    .await
                    .map_err(|e| format!("Unable to read block number from eth1 node: {:?}", e))?;

                if block_number > 0.into() {
                    info!(
                        log,
                        "Eth1 node is synced";
                        "head_block" => format!("{}", block_number),
                    );
                    break;
                } else {
                    delay_until(Instant::now() + SYNCING_STATE_RETRY_DELAY).await;
                    info!(
                        log,
                        "Waiting for eth1 node to sync";
                        "current_block" => 0,
                    );
                }
            }
        }
    }

    Ok(())
}
