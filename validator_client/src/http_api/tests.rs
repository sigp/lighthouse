#![cfg(test)]
// #![cfg(not(debug_assertions))]

mod keystores;

use crate::http_api::test_utils::{
    ApiTester, HdValidatorScenario, KeystoreValidatorScenario, Web3SignerValidatorScenario,
    TEST_DEFAULT_FEE_RECIPIENT,
};
use account_utils::{random_password, random_password_string, ZeroizeString};
use eth2::lighthouse_vc::types::*;
use eth2_keystore::KeystoreBuilder;
use std::future::Future;

type E = MainnetEthSpec;

#[tokio::test]
async fn invalid_pubkey() {
    ApiTester::new()
        .await
        .invalidate_api_token()
        .test_get_lighthouse_version_invalid()
        .await;
}

#[tokio::test]
async fn routes_with_invalid_auth() {
    ApiTester::new()
        .await
        .test_with_invalid_auth(|client| async move { client.get_lighthouse_version().await })
        .await
        .test_with_invalid_auth(|client| async move { client.get_lighthouse_health().await })
        .await
        .test_with_invalid_auth(|client| async move {
            client.get_lighthouse_spec::<types::Config>().await
        })
        .await
        .test_with_invalid_auth(|client| async move { client.get_lighthouse_validators().await })
        .await
        .test_with_invalid_auth(|client| async move {
            client
                .get_lighthouse_validators_pubkey(&PublicKeyBytes::empty())
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move {
            client
                .post_lighthouse_validators(vec![ValidatorRequest {
                    enable: <_>::default(),
                    description: <_>::default(),
                    graffiti: <_>::default(),
                    suggested_fee_recipient: <_>::default(),
                    gas_limit: <_>::default(),
                    builder_proposals: <_>::default(),
                    deposit_gwei: <_>::default(),
                }])
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move {
            client
                .post_lighthouse_validators_mnemonic(&CreateValidatorsMnemonicRequest {
                    mnemonic: String::default().into(),
                    key_derivation_path_offset: <_>::default(),
                    validators: <_>::default(),
                })
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move {
            let password = random_password();
            let keypair = Keypair::random();
            let keystore = KeystoreBuilder::new(&keypair, password.as_bytes(), String::new())
                .unwrap()
                .build()
                .unwrap();
            client
                .post_lighthouse_validators_keystore(&KeystoreValidatorsPostRequest {
                    password: String::default().into(),
                    enable: <_>::default(),
                    keystore,
                    graffiti: <_>::default(),
                    suggested_fee_recipient: <_>::default(),
                    gas_limit: <_>::default(),
                    builder_proposals: <_>::default(),
                })
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move {
            client
                .patch_lighthouse_validators(&PublicKeyBytes::empty(), Some(false), None, None)
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move { client.get_keystores().await })
        .await
        .test_with_invalid_auth(|client| async move {
            let password = random_password_string();
            let keypair = Keypair::random();
            let keystore = KeystoreBuilder::new(&keypair, password.as_ref(), String::new())
                .unwrap()
                .build()
                .map(KeystoreJsonStr)
                .unwrap();
            client
                .post_keystores(&ImportKeystoresRequest {
                    keystores: vec![keystore],
                    passwords: vec![password],
                    slashing_protection: None,
                })
                .await
        })
        .await
        .test_with_invalid_auth(|client| async move {
            let keypair = Keypair::random();
            client
                .delete_keystores(&DeleteKeystoresRequest {
                    pubkeys: vec![keypair.pk.compress()],
                })
                .await
        })
        .await;
}

#[tokio::test]
async fn simple_getters() {
    ApiTester::new()
        .await
        .test_get_lighthouse_version()
        .await
        .test_get_lighthouse_health()
        .await
        .test_get_lighthouse_spec()
        .await;
}

#[tokio::test]
async fn hd_validator_creation() {
    ApiTester::new()
        .await
        .assert_enabled_validators_count(0)
        .assert_validators_count(0)
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: true,
            key_derivation_path_offset: 0,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2)
        .create_hd_validators(HdValidatorScenario {
            count: 1,
            specify_mnemonic: false,
            key_derivation_path_offset: 0,
            disabled: vec![0],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(3)
        .create_hd_validators(HdValidatorScenario {
            count: 0,
            specify_mnemonic: true,
            key_derivation_path_offset: 4,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(3);
}

#[tokio::test]
async fn validator_enabling() {
    ApiTester::new()
        .await
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: false,
            key_derivation_path_offset: 0,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2)
        .set_validator_enabled(0, false)
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(2)
        .set_validator_enabled(0, true)
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2);
}

#[tokio::test]
async fn validator_gas_limit() {
    ApiTester::new()
        .await
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: false,
            key_derivation_path_offset: 0,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2)
        .set_gas_limit(0, 500)
        .await
        .assert_gas_limit(0, 500)
        .await
        // Update gas limit while validator is disabled.
        .set_validator_enabled(0, false)
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(2)
        .set_gas_limit(0, 1000)
        .await
        .set_validator_enabled(0, true)
        .await
        .assert_enabled_validators_count(2)
        .assert_gas_limit(0, 1000)
        .await;
}

#[tokio::test]
async fn validator_builder_proposals() {
    ApiTester::new()
        .await
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: false,
            key_derivation_path_offset: 0,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2)
        .set_builder_proposals(0, true)
        .await
        // Test setting builder proposals while the validator is disabled
        .set_validator_enabled(0, false)
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(2)
        .set_builder_proposals(0, false)
        .await
        .set_validator_enabled(0, true)
        .await
        .assert_enabled_validators_count(2)
        .assert_builder_proposals(0, false)
        .await;
}

#[tokio::test]
async fn keystore_validator_creation() {
    ApiTester::new()
        .await
        .assert_enabled_validators_count(0)
        .assert_validators_count(0)
        .create_keystore_validators(KeystoreValidatorScenario {
            correct_password: true,
            enabled: true,
        })
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(1)
        .create_keystore_validators(KeystoreValidatorScenario {
            correct_password: false,
            enabled: true,
        })
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(1)
        .create_keystore_validators(KeystoreValidatorScenario {
            correct_password: true,
            enabled: false,
        })
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(2);
}

#[tokio::test]
async fn web3signer_validator_creation() {
    ApiTester::new()
        .await
        .assert_enabled_validators_count(0)
        .assert_validators_count(0)
        .create_web3signer_validators(Web3SignerValidatorScenario {
            count: 1,
            enabled: true,
        })
        .await
        .assert_enabled_validators_count(1)
        .assert_validators_count(1);
}
