use crate::ValidatorStore;
use account_utils::validator_definitions::{SigningDefinition, ValidatorDefinition};
use account_utils::{
    eth2_wallet::{bip39::Mnemonic, WalletBuilder},
    random_mnemonic, random_password, ZeroizeString,
};
use eth2::lighthouse_vc::types::{self as api_types};
use slot_clock::SlotClock;
use std::path::Path;
use types::ChainSpec;
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;

/// Create some validator EIP-2335 keystores and store them on disk. Then, enroll the validators in
/// this validator client.
///
/// Returns the list of created validators and the mnemonic used to derive them via EIP-2334.
///
/// ## Detail
///
/// If `mnemonic_opt` is not supplied it will be randomly generated and returned in the response.
///
/// If `key_derivation_path_offset` is supplied then the EIP-2334 validator index will start at
/// this point.
pub async fn create_validators_mnemonic<P: AsRef<Path>, T: 'static + SlotClock, E: EthSpec>(
    mnemonic_opt: Option<Mnemonic>,
    key_derivation_path_offset: Option<u32>,
    validator_requests: &[api_types::ValidatorRequest],
    validator_dir: P,
    validator_store: &ValidatorStore<T, E>,
    spec: &ChainSpec,
) -> Result<(Vec<api_types::CreatedValidator>, Mnemonic), warp::Rejection> {
    let mnemonic = mnemonic_opt.unwrap_or_else(random_mnemonic);

    let wallet_password = random_password();
    let mut wallet =
        WalletBuilder::from_mnemonic(&mnemonic, wallet_password.as_bytes(), String::new())
            .and_then(|builder| builder.build())
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "unable to create EIP-2386 wallet: {:?}",
                    e
                ))
            })?;

    if let Some(nextaccount) = key_derivation_path_offset {
        wallet.set_nextaccount(nextaccount).map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "unable to set wallet nextaccount: {:?}",
                e
            ))
        })?;
    }

    let mut validators = Vec::with_capacity(validator_requests.len());

    for request in validator_requests {
        let voting_password = random_password();
        let withdrawal_password = random_password();
        let voting_password_string = ZeroizeString::from(
            String::from_utf8(voting_password.as_bytes().to_vec()).map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "locally generated password is not utf8: {:?}",
                    e
                ))
            })?,
        );

        let mut keystores = wallet
            .next_validator(
                wallet_password.as_bytes(),
                voting_password.as_bytes(),
                withdrawal_password.as_bytes(),
            )
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "unable to create validator keys: {:?}",
                    e
                ))
            })?;

        keystores
            .voting
            .set_description(request.description.clone());
        keystores
            .withdrawal
            .set_description(request.description.clone());

        let voting_pubkey = format!("0x{}", keystores.voting.pubkey())
            .parse()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "created invalid public key: {:?}",
                    e
                ))
            })?;

        let validator_dir = ValidatorDirBuilder::new(validator_dir.as_ref().into())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(request.deposit_gwei, spec)
            .store_withdrawal_keystore(false)
            .build()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to build validator directory: {:?}",
                    e
                ))
            })?;

        let eth1_deposit_data = validator_dir
            .eth1_deposit_data()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to read local deposit data: {:?}",
                    e
                ))
            })?
            .ok_or_else(|| {
                warp_utils::reject::custom_server_error(
                    "failed to create local deposit data: {:?}".to_string(),
                )
            })?;

        if eth1_deposit_data.deposit_data.amount != request.deposit_gwei {
            return Err(warp_utils::reject::custom_server_error(format!(
                "invalid deposit_gwei {}, expected {}",
                eth1_deposit_data.deposit_data.amount, request.deposit_gwei
            )));
        }

        // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
        let voting_keystore_path = validator_dir.voting_keystore_path();
        drop(validator_dir);

        validator_store
            .add_validator_keystore(
                voting_keystore_path,
                voting_password_string,
                request.enable,
                request.graffiti.clone(),
            )
            .await
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to initialize validator: {:?}",
                    e
                ))
            })?;

        validators.push(api_types::CreatedValidator {
            enabled: request.enable,
            description: request.description.clone(),
            graffiti: request.graffiti.clone(),
            voting_pubkey,
            eth1_deposit_tx_data: eth2_serde_utils::hex::encode(&eth1_deposit_data.rlp),
            deposit_gwei: request.deposit_gwei,
        });
    }

    Ok((validators, mnemonic))
}

pub async fn create_validators_web3signer<T: 'static + SlotClock, E: EthSpec>(
    validator_requests: &[api_types::Web3SignerValidatorRequest],
    validator_store: &ValidatorStore<T, E>,
) -> Result<(), warp::Rejection> {
    for request in validator_requests {
        let validator_definition = ValidatorDefinition {
            enabled: request.enable,
            voting_public_key: request.voting_public_key.clone(),
            graffiti: request.graffiti.clone(),
            description: request.description.clone(),
            signing_definition: SigningDefinition::Web3Signer {
                url: request.url.clone(),
                root_certificate_path: request.root_certificate_path.clone(),
                request_timeout_ms: request.request_timeout_ms,
            },
        };
        validator_store
            .add_validator(validator_definition)
            .await
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to initialize validator: {:?}",
                    e
                ))
            })?;
    }

    Ok(())
}
