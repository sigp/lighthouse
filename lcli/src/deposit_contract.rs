use clap::ArgMatches;
use environment::Environment;
use eth1_test_rig::{DelayThenDeposit, DepositContract};
use futures::Future;
use std::time::Duration;
use types::{test_utils::generate_deterministic_keypair, EthSpec, Hash256};
use web3::{transports::Http, Web3};

pub fn run_deposit_contract<T: EthSpec>(
    mut env: Environment<T>,
    matches: &ArgMatches,
) -> Result<(), String> {
    let count = matches
        .value_of("count")
        .ok_or_else(|| "Deposit count not specified")?
        .parse::<usize>()
        .map_err(|e| format!("Failed to parse deposit count: {}", e))?;

    let delay = matches
        .value_of("delay")
        .ok_or_else(|| "Deposit count not specified")?
        .parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|e| format!("Failed to parse deposit count: {}", e))?;

    let confirmations = matches
        .value_of("confirmations")
        .ok_or_else(|| "Confirmations not specified")?
        .parse::<usize>()
        .map_err(|e| format!("Failed to parse confirmations: {}", e))?;

    let endpoint = matches
        .value_of("endpoint")
        .ok_or_else(|| "Endpoint not specified")?;

    let (_event_loop, transport) = Http::new(&endpoint).map_err(|e| {
        format!(
            "Failed to start HTTP transport connected to ganache: {:?}",
            e
        )
    })?;
    let web3 = Web3::new(transport);

    let deposit_contract = env
        .runtime()
        .block_on(DepositContract::deploy(web3, confirmations))
        .map_err(|e| format!("Failed to deploy contract: {}", e))?;

    info!(
        "Deposit contract deployed. Address: {}",
        deposit_contract.address()
    );

    env.runtime()
        .block_on(do_deposits::<T>(deposit_contract, count, delay))
        .map_err(|e| format!("Failed to submit deposits: {}", e))?;

    Ok(())
}

fn do_deposits<T: EthSpec>(
    deposit_contract: DepositContract,
    count: usize,
    delay: Duration,
) -> impl Future<Item = (), Error = String> {
    let deposits = (0..count)
        .map(|i| DelayThenDeposit {
            deposit: deposit_contract.deposit_helper::<T>(
                generate_deterministic_keypair(i),
                Hash256::from_low_u64_le(i as u64),
                32_000_000_000,
            ),
            delay,
        })
        .collect();

    deposit_contract.deposit_multiple(deposits)
}
