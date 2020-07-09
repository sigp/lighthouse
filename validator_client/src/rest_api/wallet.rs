use super::errors::{ApiError, ApiResult};
use super::response_builder::ResponseBuilder;
use eth2_wallet_manager::{WalletManager, WalletType};
use hyper::{body, Body, Request};
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::path::PathBuf;
use types::EthSpec;

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
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })?;

    let mgr = WalletManager::open(&wallet_dir).map_err(|e| {
        ApiError::ServerError(format!(
            "Unable to open wallet directory {:?}: {:?}",
            wallet_dir, e
        ))
    })?;

    let wallet_password_path = secrets_dir.join(format!("{}.pass", body.wallet_name));

    // TODO: make mnemonic optional.

    let (wallet, mnemonic) = mgr
        .create_wallet_and_secrets(body.wallet_name, WalletType::Hd, wallet_password_path, None)
        .map_err(|e| ApiError::ServerError(format!("Unable to create wallet: {:?}", e)))?;

    response_builder?.body_no_ssz(&CreateWalletValidatorResponse {
        wallet_name: wallet.wallet().name().into(),
        mnemonic: Some(mnemonic.into()),
    })
}
