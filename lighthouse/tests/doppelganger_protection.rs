use local_testnet::config::IntegrationTestConfig;
use types::Epoch;

#[test]
fn doppelganger_test() {
    let mut test = IntegrationTestConfig::new(std::env!("CARGO_BIN_EXE_lighthouse"))
        .expect("should parse testnet config");
    let testnet = test.start_testnet().expect("should start testnet");

    testnet
        .wait_epochs(Epoch::new(2))
        .add_validator()
        .wait_epochs(Epoch::new(3));
}
