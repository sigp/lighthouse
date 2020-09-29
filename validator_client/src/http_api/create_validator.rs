use crate::InitializedValidators;
use account_utils::{
    eth2_wallet::{bip39::Mnemonic, WalletBuilder},
    random_mnemonic, random_password,
    validator_definitions::ValidatorDefinition,
    ZeroizeString,
};
use eth2::lighthouse_vc::types::{self as api_types};
use parking_lot::RwLock;
use std::path::Path;
use types::ChainSpec;
use validator_dir::Builder as ValidatorDirBuilder;

pub fn create_validators<P: AsRef<Path>>(
    mnemonic_opt: Option<Mnemonic>,
    validator_requests: &[api_types::ValidatorRequest],
    data_dir: P,
    initialized_validators: &RwLock<InitializedValidators>,
    spec: &ChainSpec,
) -> Result<(Vec<api_types::CreatedValidator>, Mnemonic), warp::Rejection> {
    let mnemonic = mnemonic_opt.unwrap_or_else(|| random_mnemonic());

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

    let mut validators = Vec::with_capacity(validator_requests.len());

    for request in validator_requests {
        let voting_password = random_password();
        let withdrawal_password = random_password();

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

        keystores.voting.set_name(request.name.clone());
        keystores.withdrawal.set_name(request.name.clone());

        let voting_pubkey = format!("0x{}", keystores.voting.pubkey())
            .parse()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "created invalid public key: {:?}",
                    e
                ))
            })?;

        let validator_dir = ValidatorDirBuilder::new(data_dir.as_ref().into())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(request.deposit_gwei, &spec)
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

        let voting_password = ZeroizeString::from(
            String::from_utf8(voting_password.as_bytes().to_vec()).map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "locally generated password is not utf8: {:?}",
                    e
                ))
            })?,
        );

        let mut validator_def = ValidatorDefinition::new_keystore_with_password(
            validator_dir.voting_keystore_path(),
            Some(voting_password),
        )
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "failed to create validator definitions: {:?}",
                e
            ))
        })?;

        validator_def.enabled = request.enable;

        tokio::runtime::Handle::current()
            .block_on(initialized_validators.write().add_definition(validator_def))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to initialize validator: {:?}",
                    e
                ))
            })?;

        validators.push(api_types::CreatedValidator {
            enabled: true,
            name: request.name.clone(),
            voting_pubkey: voting_pubkey,
            eth1_deposit_tx_data: serde_utils::hex::encode(&eth1_deposit_data.rlp),
            deposit_gwei: request.deposit_gwei,
        });
    }

    Ok((validators, mnemonic))
}
