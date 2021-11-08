//! Implementation of the standard keystore management API.
use crate::{signing_method::SigningMethod, InitializedValidators, ValidatorStore};
use account_utils::ZeroizeString;
use eth2::lighthouse_vc::std_types::{
    DeleteKeystoreStatus, DeleteKeystoresRequest, DeleteKeystoresResponse, ImportKeystoreStatus,
    ImportKeystoresRequest, ImportKeystoresResponse, ListKeystoresResponse, SingleKeystoreResponse,
    Status,
};
use eth2_keystore::Keystore;
use slog::{info, warn, Logger};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Weak;
use tokio::runtime::Runtime;
use types::{EthSpec, PublicKeyBytes};
use validator_dir::Builder as ValidatorDirBuilder;
use warp::Rejection;
use warp_utils::reject::{custom_bad_request, custom_server_error};

pub fn list<T: SlotClock + 'static, E: EthSpec>(
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ListKeystoresResponse {
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let initialized_validators = initialized_validators_rwlock.read();

    let keystores = initialized_validators
        .validator_definitions()
        .iter()
        .filter(|def| def.enabled && def.signing_definition.is_local_keystore())
        .map(|def| {
            let validating_pubkey = def.voting_public_key.compress();

            let derivation_path = initialized_validators
                .signing_method(&validating_pubkey)
                .and_then(|signing_method| match *signing_method {
                    SigningMethod::LocalKeystore {
                        ref voting_keystore,
                        ..
                    } => voting_keystore.path(),
                    SigningMethod::Web3Signer { .. } => None,
                });

            SingleKeystoreResponse {
                validating_pubkey,
                derivation_path,
                readonly: None,
            }
        })
        .collect::<Vec<_>>();

    ListKeystoresResponse { data: keystores }
}

pub fn import<T: SlotClock + 'static, E: EthSpec>(
    request: ImportKeystoresRequest,
    validator_dir: PathBuf,
    validator_store: Arc<ValidatorStore<T, E>>,
    runtime: Weak<Runtime>,
    log: Logger,
) -> Result<ImportKeystoresResponse, Rejection> {
    info!(
        log,
        "Importing keystores via standard HTTP API";
        "count" => request.keystores.len(),
    );

    // Import slashing protection data before keystores, so that new keystores don't start signing
    // without it.
    if let Some(slashing_protection) = request.slashing_protection {
        // Warn for missing slashing protection.
        for keystore in &request.keystores {
            if let Some(public_key) = keystore.public_key() {
                let pubkey_bytes = public_key.compress();
                if !slashing_protection
                    .data
                    .iter()
                    .any(|data| data.pubkey == pubkey_bytes)
                {
                    warn!(
                        log,
                        "Slashing protection data not provided";
                        "public_key" => ?public_key,
                    );
                }
            }
        }

        validator_store
            .import_slashing_protection(slashing_protection)
            .map_err(|e| {
                custom_bad_request(format!("error importing slashing protection: {:?}", e))
            })?
    } else {
        warn!(log, "No slashing protection data provided with keystores");
    }

    // Import each keystore. Some keystores may fail to be imported, so we record a status for each.
    let mut statuses = Vec::with_capacity(request.keystores.len());

    // FIXME(sproul): check and test different length keystores vs passwords
    for (keystore, password) in request
        .keystores
        .into_iter()
        .zip(request.passwords.into_iter())
    {
        let pubkey_str = keystore.pubkey().to_string();

        let status = if let Some(runtime) = runtime.upgrade() {
            match import_single_keystore(
                keystore,
                password,
                validator_dir.clone(),
                &validator_store,
                runtime,
            ) {
                Ok(status) => Status::ok(status),
                Err(e) => {
                    warn!(
                        log,
                        "Error importing keystore, skipped";
                        "pubkey" => pubkey_str,
                        "error" => ?e,
                    );
                    Status::error(ImportKeystoreStatus::Error, e)
                }
            }
        } else {
            Status::error(
                ImportKeystoreStatus::Error,
                "validator client shutdown".into(),
            )
        };
        statuses.push(status);
    }

    Ok(ImportKeystoresResponse { data: statuses })
}

fn import_single_keystore<T: SlotClock + 'static, E: EthSpec>(
    keystore: Keystore,
    password: ZeroizeString,
    validator_dir_path: PathBuf,
    validator_store: &ValidatorStore<T, E>,
    runtime: Arc<Runtime>,
) -> Result<ImportKeystoreStatus, String> {
    // Check if the validator key already exists.
    let pubkey = keystore
        .public_key()
        .ok_or_else(|| format!("invalid pubkey: {}", keystore.pubkey()))?;
    if validator_store
        .initialized_validators()
        .read()
        .is_enabled(&pubkey)
        .unwrap_or(false)
    {
        return Ok(ImportKeystoreStatus::Duplicate);
    }

    let validator_dir = ValidatorDirBuilder::new(validator_dir_path)
        .voting_keystore(keystore, password.as_ref())
        .store_withdrawal_keystore(false)
        .build()
        .map_err(|e| format!("failed to build validator directory: {:?}", e))?;

    // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
    let voting_keystore_path = validator_dir.voting_keystore_path();
    drop(validator_dir);

    runtime
        .block_on(validator_store.add_validator_keystore(
            voting_keystore_path,
            password,
            true,
            None,
        ))
        .map_err(|e| format!("failed to initialize validator: {:?}", e))?;

    Ok(ImportKeystoreStatus::Imported)
}

pub fn delete<T: SlotClock + 'static, E: EthSpec>(
    request: DeleteKeystoresRequest,
    validator_store: Arc<ValidatorStore<T, E>>,
    runtime: Weak<Runtime>,
    log: Logger,
) -> Result<DeleteKeystoresResponse, Rejection> {
    // Remove from initialized validators.
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let mut initialized_validators = initialized_validators_rwlock.write();

    let mut statuses = request
        .pubkeys
        .iter()
        .map(|pubkey_bytes| {
            match delete_single_keystore(pubkey_bytes, &mut initialized_validators, runtime.clone())
            {
                Ok(status) => Status::ok(status),
                Err(error) => {
                    warn!(
                        log,
                        "Error deleting keystore";
                        "pubkey" => ?pubkey_bytes,
                        "error" => ?error,
                    );
                    Status::error(DeleteKeystoreStatus::Error, error)
                }
            }
        })
        .collect::<Vec<_>>();

    let slashing_protection = validator_store
        .export_slashing_protection_for_keys(&request.pubkeys)
        .map_err(|e| {
            custom_server_error(format!("error exporting slashing protection: {:?}", e))
        })?;

    // Update stasuses based on availability of slashing protection data.
    for (pubkey, status) in request.pubkeys.iter().zip(statuses.iter_mut()) {
        if status.status == DeleteKeystoreStatus::NotFound
            && slashing_protection
                .data
                .iter()
                .any(|interchange_data| interchange_data.pubkey == *pubkey)
        {
            status.status = DeleteKeystoreStatus::NotActive;
        }
    }

    Ok(DeleteKeystoresResponse {
        data: statuses,
        slashing_protection,
    })
}

fn delete_single_keystore(
    pubkey_bytes: &PublicKeyBytes,
    initialized_validators: &mut InitializedValidators,
    runtime: Weak<Runtime>,
) -> Result<DeleteKeystoreStatus, String> {
    if let Some(runtime) = runtime.upgrade() {
        let pubkey = pubkey_bytes
            .decompress()
            .map_err(|e| format!("invalid pubkey, {:?}: {:?}", pubkey_bytes, e))?;

        runtime
            .block_on(initialized_validators.delete_definition_and_keystore(&pubkey))
            .map_err(|e| format!("unable to disable and delete: {:?}", e))
    } else {
        Err("validator client shutdown".into())
    }
}
