use c_kzg::KzgSettings as MainnetSettings;
use c_kzg_minimal::KzgSettings as MinimalSettings;
use kzg::TrustedSetup;
use std::fs::File;

#[test]
fn test_minimal() {
    assert_ne!(
        c_kzg::FIELD_ELEMENTS_PER_BLOB,
        c_kzg_minimal::FIELD_ELEMENTS_PER_BLOB
    );

    let mainnet_ts_file = File::open("./trusted_setup_mainnet.json").unwrap();
    let mainnet_ts: TrustedSetup = serde_json::from_reader(mainnet_ts_file).unwrap();

    let _mainnet_settings =
        MainnetSettings::load_trusted_setup(mainnet_ts.g1_points(), mainnet_ts.g2_points())
            .unwrap();
    println!("loaded mainnet");

    let minimal_ts_file = File::open("./trusted_setup_minimal.json").unwrap();
    let minimal_ts: TrustedSetup = serde_json::from_reader(minimal_ts_file).unwrap();

    let _minimal_settings =
        MinimalSettings::load_trusted_setup(minimal_ts.g1_points(), minimal_ts.g2_points())
            .unwrap();
    println!("loaded minimal");
}
