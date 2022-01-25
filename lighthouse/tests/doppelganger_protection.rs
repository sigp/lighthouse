use local_testnet::config::IntegrationTestConfig;
use types::Epoch;

#[tokio::test]
async fn doppelganger_test() {
    let mut test = IntegrationTestConfig::new(std::env!("CARGO_BIN_EXE_lighthouse"))
        .expect("should parse testnet config");
    let testnet = test.start_testnet().expect("should start testnet");

    testnet
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(2))
        .expect("should wait")
        .add_validator()
        .expect("should add doppelganger")
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(3))
        .expect("should wait")
        .check_all_active()
        .await;
}
