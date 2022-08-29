use beacon_chain::test_utils::test_spec;
use beacon_chain_fuzz::{Config, LogConfig, LogInterceptor, Runner, TestHarness};
use tokio::runtime::Runtime;
use types::Keypair;

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

fn get_harness(id: String, log_config: LogConfig, keypairs: &[Keypair]) -> TestHarness<E> {
    let spec = test_spec::<E>();

    let log = LogInterceptor::new(id, log_config).into_logger();

    let harness = TestHarness::builder(E::default())
        .spec(spec)
        .logger(log)
        .keypairs(keypairs.to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness
}

fn main() {
    fuzz!(|data: &[u8]| {
        let config = Config::from_env();
        let rt = Runtime::new().unwrap();

        let mut runner = Runner::new(data, config, get_harness);

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
