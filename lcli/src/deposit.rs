use clap::ArgMatches;
use environment::Environment;
use eth1_test_rig::DepositContract;
use types::{Address, EthSpec};

use web3::{transports::Http, Web3};

pub fn run<T: EthSpec>(env: Environment<T>, matches: &ArgMatches<'_>) -> Result<(), String> {
    let eth1_http: String = clap_utils::parse_required(matches, "eth1-http")?;
    let validator_count: usize = clap_utils::parse_required(matches, "validator-count")?;
    let contract_address: Address =
        clap_utils::parse_required(matches, "deposit-contract-address")?;

    let transport =
        Http::new(&eth1_http).map_err(|e| format!("Unable to connect to eth1 HTTP: {:?}", e))?;
    let web3 = Web3::new(transport);

    env.runtime().block_on(async {
        let contract: DepositContract =
            eth1_test_rig::DepositContract::connect(web3, contract_address)
                .map_err(|e| format!("Failed to connect to deposit contract: {:?}", e))?;

        // Deposit insecure validators to the deposit contract created
        let amount = env.eth2_config.spec.max_effective_balance;
        for i in 0..validator_count {
            println!("Submitting deposit for validator {}...", i);
            contract.deposit_deterministic_async::<T>(i, amount).await?;
        }
        Ok(())
    })
}
