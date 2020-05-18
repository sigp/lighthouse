#![cfg(test)]
use eth2_interop_keypairs::{keypair as reference_keypair, keypairs_from_yaml_file};
use std::path::PathBuf;

fn yaml_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("specs")
        .join("keygen_10_validators.yaml")
}

#[test]
fn load_from_yaml() {
    let keypairs = keypairs_from_yaml_file(yaml_path()).expect("should read keypairs from file");

    keypairs.into_iter().enumerate().for_each(|(i, keypair)| {
        assert_eq!(
            keypair,
            reference_keypair(i),
            "Decoded key {} does not match generated key",
            i
        )
    });
}
