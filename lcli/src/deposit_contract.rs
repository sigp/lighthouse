use clap::ArgMatches;
use environment::Environment;
use eth1_test_rig::{DelayThenDeposit, DepositContract};
use futures::Future;
use std::time::Duration;
use types::{test_utils::generate_deterministic_keypair, EthSpec, Hash256};

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
        .map(|millis| Duration::from_millis(millis))
        .map_err(|e| format!("Failed to parse deposit count: {}", e))?;

    let endpoint = matches
        .value_of("endpoint")
        .ok_or_else(|| "Endpoint not specified")?;

    let deposit_contract = DepositContract::deploy(env.runtime(), endpoint)
        .map_err(|e| format!("Failed to deploy contract: {}", e))?;

    info!("Deposit contract address: {}", deposit_contract.address());

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
    let utils = deposit_contract.unsafe_blocking_utils();

    let deposits = (0..count)
        .into_iter()
        .map(|i| DelayThenDeposit {
            deposit: utils.get_deposit::<T>(
                generate_deterministic_keypair(i),
                Hash256::from_low_u64_le(i as u64),
                32_000_000_000,
            ),
            delay,
        })
        .collect();

    deposit_contract.deposit_multiple(deposits)
}
