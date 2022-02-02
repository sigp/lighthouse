use clap_utils::flags::ENABLE_DOPPELGANGER_PROTECTION_FLAG;
use local_testnet::config::IntegrationTestConfig;
use serial_test::serial;
use std::thread;
use types::Epoch;

#[tokio::test]
#[serial]
async fn doppelganger_detected() {
    let testnet = thread::spawn(|| {
        let mut test = IntegrationTestConfig::new_with_config(
            std::env!("CARGO_BIN_EXE_lighthouse"),
            "./tests/doppelganger_protection/doppelganger_detected.toml",
        )
        .expect("should parse testnet config");
        let testnet = test.start_testnet().expect("should start testnet");
        testnet
    })
    .join()
    .unwrap();

    testnet
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(2))
        .add_validator()
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(3))
        .assert_inactive_validators(1)
        .await;
}

#[tokio::test]
#[serial]
async fn no_doppelganger_detected() {
    let testnet = thread::spawn(|| {
        let mut test = IntegrationTestConfig::new_with_config(
            std::env!("CARGO_BIN_EXE_lighthouse"),
            "./tests/doppelganger_protection/no_doppelganger_detected.toml",
        )
        .expect("should parse testnet config");
        let testnet = test.start_testnet().expect("should start testnet");
        testnet
    })
    .join()
    .unwrap();

    testnet
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(2))
        .add_validator_with_config(|config| {
            config.insert(
                ENABLE_DOPPELGANGER_PROTECTION_FLAG.to_string(),
                "true".to_string(),
            );
        })
        .check_all_active()
        .await
        .wait_epochs(Epoch::new(3))
        .assert_inactive_validators(0)
        .await;
}
