use beacon_chain::test_utils::test_spec;
use beacon_chain_fuzz::{Config, LogConfig, LogInterceptor, Runner, TestHarness};
use tokio::runtime::Runtime;
use types::{ChainSpec, ForkName, Keypair, Uint256};

const TEST_FORK: ForkName = ForkName::Capella;

#[cfg(feature = "afl")]
use afl::fuzz;

#[cfg(not(feature = "afl"))]
macro_rules! fuzz {
    ($e:expr) => {
        use std::io::Read;

        let mut stdin = std::io::stdin();
        let mut data = vec![];
        stdin.read_to_end(&mut data).unwrap();
        ($e)(&data)
    };
}

// Use a `cfg` for the spec to avoid bloating the binary.
#[cfg(all(feature = "minimal", not(feature = "mainnet")))]
type E = types::MinimalEthSpec;
#[cfg(feature = "mainnet")]
type E = types::MainnetEthSpec;

fn get_harness(
    id: String,
    log_config: LogConfig,
    spec: ChainSpec,
    keypairs: &[Keypair],
) -> TestHarness<E> {
    let log = LogInterceptor::new(id, log_config).into_logger();

    // Start from PoS.
    let terminal_block_number = 0;

    let harness = TestHarness::builder(E::default())
        .spec(spec)
        .logger(log)
        .keypairs(keypairs.to_vec())
        .mock_execution_layer_generic(terminal_block_number)
        .fresh_ephemeral_store()
        .build();
    harness
}

fn main() {
    fuzz!(|data: &[u8]| {
        let config = Config::from_env();
        let rt = Runtime::new().unwrap();

        // FIXME(sproul): need to actually get execution enabled
        let mut spec = TEST_FORK.make_genesis_spec(test_spec::<E>());
        spec.terminal_total_difficulty = Uint256::zero();
        let mut runner = Runner::new(data, config, spec, get_harness);

        match rt.block_on(async move { runner.run().await }) {
            Ok(()) => (),
            Err(arbitrary::Error::NotEnoughData) => {
                println!("aborted run due to lack of entropy");
            }
            Err(_) => {
                panic!("bad arbitrary usage");
            }
        }
    });
}
