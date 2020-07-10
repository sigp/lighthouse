use super::response_builder::ResponseBuilder;
use super::{
    common::wallet_manager,
    errors::{ApiError, ApiResult},
};
use eth2_wallet_manager::WalletType;
use hyper::{body, Body, Request};
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::path::PathBuf;
use types::EthSpec;

const MIN_SEED_LENGTH: usize = 32;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct CreateWalletValidatorRequest {
    pub wallet_name: String,
    // TODO: zeroize.
    pub seed: Option<Vec<u8>>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct CreateWalletValidatorResponse {
    pub wallet_name: String,
    // TODO: zeroize.
    pub mnemonic: Option<String>,
}

pub async fn create_wallet<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    wallet_dir: PathBuf,
    secrets_dir: PathBuf,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    let body: CreateWalletValidatorRequest = body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into CreateWalletValidatorRequest: {:?}",
                    e
                ))
            })
        })?;

    // Check that the seed is reasonable.
    if let Some(seed) = body.seed.as_ref() {
        // Seed must meet a minimum length requirement.
        if seed.len() < MIN_SEED_LENGTH {
            return Err(ApiError::BadRequest(format!(
                "Seed is {} bytes. Must be at least {} bytes.",
                seed.len(),
                MIN_SEED_LENGTH
            )));
        }

        // Seed cannot be all-zeros.
        if seed.iter().all(|byte| *byte == 0) {
            return Err(ApiError::BadRequest(
                "Seed cannot be all zeros.".to_string(),
            ));
        }
    }

    let wallet_password_path = secrets_dir.join(format!("{}.pass", body.wallet_name));

    let (wallet, mnemonic) = wallet_manager(&wallet_dir)?
        .create_wallet_and_secrets(
            body.wallet_name,
            WalletType::Hd,
            wallet_password_path,
            body.seed.as_ref().map(|bytes| bytes.as_slice()),
            None,
        )
        .map_err(|e| ApiError::ServerError(format!("Unable to create wallet: {:?}", e)))?;

    response_builder?.body_no_ssz(&CreateWalletValidatorResponse {
        wallet_name: wallet.wallet().name().into(),
        mnemonic: mnemonic.map(Into::into),
    })
}

pub async fn list_wallets<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    wallet_dir: PathBuf,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);

    let names: Vec<String> = wallet_manager(&wallet_dir)?
        .wallets()
        .map(|map| map.into_iter().map(|(name, _uuid)| name).collect())
        .map_err(|e| ApiError::ServerError(format!("Unable to list wallets: {:?}", e)))?;

    response_builder?.body_no_ssz(&names)
}
