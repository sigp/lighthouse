use clap::ArgMatches;
use environment::Environment;
use types::EthSpec;

use web3::{transports::Http, Web3};

pub fn run<T: EthSpec>(env: Environment<T>, matches: &ArgMatches<'_>) -> Result<(), String> {
    let eth1_http: String = clap_utils::parse_required(matches, "eth1-http")?;
    let confirmations: usize = clap_utils::parse_required(matches, "confirmations")?;
    let validator_count: Option<usize> = clap_utils::parse_optional(matches, "validator-count")?;

    let transport =
        Http::new(&eth1_http).map_err(|e| format!("Unable to connect to eth1 HTTP: {:?}", e))?;
    let web3 = Web3::new(transport);

    env.runtime().block_on(async {
        let contract = eth1_test_rig::DepositContract::deploy(web3, confirmations, None)
            .await
            .map_err(|e| format!("Failed to deploy deposit contract: {:?}", e))?;

        println!("Deposit contract address: {:?}", contract.address());

        // Deposit insecure validators to the deposit contract created
        if let Some(validator_count) = validator_count {
            let amount = env.eth2_config.spec.max_effective_balance;
            for i in 0..validator_count {
                println!("Submitting deposit for validator {}...", i);
                contract.deposit_deterministic_async::<T>(i, amount).await?;
            }
        }
        Ok(())
    })
}
