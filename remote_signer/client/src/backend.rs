use crate::api_error::ApiError;
use crate::api_response::{KeysApiResponse, SignatureApiResponse};
use crate::rest_api::Context;
use crate::signing_root::get_signing_root;
use client_backend::{BackendError, Storage};
use hyper::Request;
use lazy_static::lazy_static;
use regex::Regex;
use std::sync::Arc;
use types::EthSpec;

lazy_static! {
    static ref PUBLIC_KEY_FROM_PATH_REGEX: Regex = Regex::new(r"^/[^/]+/([^/]*)").unwrap();
}

/// HTTP handler to get the list of public keys in the backend.
pub fn get_keys<E: EthSpec, S: Storage, U>(
    _: U,
    ctx: Arc<Context<E, S>>,
) -> Result<KeysApiResponse, ApiError> {
    let keys = ctx
        .backend
        .get_keys()
        .map_err(|e| ApiError::ServerError(format!("{}", e)))?;

    if keys.is_empty() {
        return Err(ApiError::NotFound("No keys found in storage.".to_string()));
    }

    Ok(KeysApiResponse { keys })
}

/// HTTP handler to sign a message with the requested key.
pub fn sign_message<E: EthSpec, S: Storage>(
    req: Request<Vec<u8>>,
    ctx: Arc<Context<E, S>>,
) -> Result<SignatureApiResponse, ApiError> {
    // Parse the request body and compute the signing root.
    let signing_root = get_signing_root::<E>(&req, ctx.spec.clone())?;

    // This public key parameter should have been validated by the router.
    // We are just going to extract it from the request.
    let path = req.uri().path().to_string();

    let rc = |path: &str| -> Result<String, String> {
        let caps = PUBLIC_KEY_FROM_PATH_REGEX.captures(path).ok_or("")?;
        let re_match = caps.get(1).ok_or("")?;
        Ok(re_match.as_str().to_string())
    };

    let public_key = rc(&path).map_err(|_| {
        ApiError::BadRequest(format!("Unable to get public key from path: {:?}", path))
    })?;

    match ctx.backend.sign_message(&public_key, signing_root) {
        Ok(signature) => Ok(SignatureApiResponse { signature }),

        Err(BackendError::KeyNotFound(_)) => {
            Err(ApiError::NotFound(format!("Key not found: {}", public_key)))
        }

        Err(BackendError::InvalidPublicKey(_)) => Err(ApiError::BadRequest(format!(
            "Invalid public key: {}",
            public_key
        ))),

        // Catches InvalidSecretKey, KeyMismatch and StorageError.
        Err(e) => Err(ApiError::ServerError(e.to_string())),
    }
}
