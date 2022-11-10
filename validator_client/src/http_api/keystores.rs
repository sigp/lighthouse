//! Implementation of the standard keystore management API.
use crate::{
    initialized_validators::Error, signing_method::SigningMethod, InitializedValidators,
    ValidatorStore,
};
use account_utils::ZeroizeString;
use eth2::lighthouse_vc::std_types::{
    DeleteKeystoreStatus, DeleteKeystoresRequest, DeleteKeystoresResponse, ImportKeystoreStatus,
    ImportKeystoresRequest, ImportKeystoresResponse, InterchangeJsonStr, KeystoreJsonStr,
    ListKeystoresResponse, SingleKeystoreResponse, Status,
};
use eth2_keystore::Keystore;
use slog::{info, warn, Logger};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::runtime::Handle;
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
        .filter(|def| def.enabled)
        .map(|def| {
            let validating_pubkey = def.voting_public_key.compress();

            let (derivation_path, readonly) = initialized_validators
                .signing_method(&validating_pubkey)
                .map_or((None, None), |signing_method| match *signing_method {
                    SigningMethod::LocalKeystore {
                        ref voting_keystore,
                        ..
                    } => (voting_keystore.path(), Some(false)),
                    SigningMethod::Web3Signer { .. } => (None, Some(true)),
                });

            SingleKeystoreResponse {
                validating_pubkey,
                derivation_path,
                readonly,
            }
        })
        .collect::<Vec<_>>();

    ListKeystoresResponse { data: keystores }
}

pub fn import<T: SlotClock + 'static, E: EthSpec>(
    request: ImportKeystoresRequest,
    validator_dir: PathBuf,
    validator_store: Arc<ValidatorStore<T, E>>,
    task_executor: TaskExecutor,
    log: Logger,
) -> Result<ImportKeystoresResponse, Rejection> {
    // Check request validity. This is the only cases in which we should return a 4xx code.
    if request.keystores.len() != request.passwords.len() {
        return Err(custom_bad_request(format!(
            "mismatched numbers of keystores ({}) and passwords ({})",
            request.keystores.len(),
            request.passwords.len(),
        )));
    }

    info!(
        log,
        "Importing keystores via standard HTTP API";
        "count" => request.keystores.len(),
    );

    // Import slashing protection data before keystores, so that new keystores don't start signing
    // without it. Do not return early on failure, propagate the failure to each key.
    let slashing_protection_status =
        if let Some(InterchangeJsonStr(slashing_protection)) = request.slashing_protection {
            // Warn for missing slashing protection.
            for KeystoreJsonStr(ref keystore) in &request.keystores {
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

            validator_store.import_slashing_protection(slashing_protection)
        } else {
            warn!(log, "No slashing protection data provided with keystores");
            Ok(())
        };

    // Import each keystore. Some keystores may fail to be imported, so we record a status for each.
    let mut statuses = Vec::with_capacity(request.keystores.len());

    for (KeystoreJsonStr(keystore), password) in request
        .keystores
        .into_iter()
        .zip(request.passwords.into_iter())
    {
        let pubkey_str = keystore.pubkey().to_string();

        let status = if let Err(e) = &slashing_protection_status {
            // Slashing protection import failed, do not attempt to import the key. Record an
            // error status.
            Status::error(
                ImportKeystoreStatus::Error,
                format!("slashing protection import failed: {:?}", e),
            )
        } else if let Some(handle) = task_executor.handle() {
            // Import the keystore.
            match import_single_keystore(
                keystore,
                password,
                validator_dir.clone(),
                &validator_store,
                handle,
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
    handle: Handle,
) -> Result<ImportKeystoreStatus, String> {
    // Check if the validator key already exists, erroring if it is a remote signer validator.
    let pubkey = keystore
        .public_key()
        .ok_or_else(|| format!("invalid pubkey: {}", keystore.pubkey()))?;
    if let Some(def) = validator_store
        .initialized_validators()
        .read()
        .validator_definitions()
        .iter()
        .find(|def| def.voting_public_key == pubkey)
    {
        if !def.signing_definition.is_local_keystore() {
            return Err("cannot import duplicate of existing remote signer validator".into());
        } else if def.enabled {
            return Ok(ImportKeystoreStatus::Duplicate);
        }
    }

    // Check that the password is correct.
    // In future we should re-structure to avoid the double decryption here. It's not as simple
    // as removing this check because `add_validator_keystore` will break if provided with an
    // invalid validator definition (`update_validators` will get stuck trying to decrypt with the
    // wrong password indefinitely).
    keystore
        .decrypt_keypair(password.as_ref())
        .map_err(|e| format!("incorrect password: {:?}", e))?;

    let validator_dir = ValidatorDirBuilder::new(validator_dir_path)
        .voting_keystore(keystore, password.as_ref())
        .store_withdrawal_keystore(false)
        .build()
        .map_err(|e| format!("failed to build validator directory: {:?}", e))?;

    // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
    let voting_keystore_path = validator_dir.voting_keystore_path();
    drop(validator_dir);

    handle
        .block_on(validator_store.add_validator_keystore(
            voting_keystore_path,
            password,
            true,
            None,
            None,
            None,
            None,
        ))
        .map_err(|e| format!("failed to initialize validator: {:?}", e))?;

    Ok(ImportKeystoreStatus::Imported)
}

pub fn delete<T: SlotClock + 'static, E: EthSpec>(
    request: DeleteKeystoresRequest,
    validator_store: Arc<ValidatorStore<T, E>>,
    task_executor: TaskExecutor,
    log: Logger,
) -> Result<DeleteKeystoresResponse, Rejection> {
    // Remove from initialized validators.
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let mut initialized_validators = initialized_validators_rwlock.write();

    let mut statuses = request
        .pubkeys
        .iter()
        .map(|pubkey_bytes| {
            match delete_single_keystore(
                pubkey_bytes,
                &mut initialized_validators,
                task_executor.clone(),
            ) {
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

    // Use `update_validators` to update the key cache. It is safe to let the key cache get a bit out
    // of date as it resets when it can't be decrypted. We update it just a single time to avoid
    // continually resetting it after each key deletion.
    if let Some(handle) = task_executor.handle() {
        handle
            .block_on(initialized_validators.update_validators())
            .map_err(|e| custom_server_error(format!("unable to update key cache: {:?}", e)))?;
    }

    // Export the slashing protection data.
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
    task_executor: TaskExecutor,
) -> Result<DeleteKeystoreStatus, String> {
    if let Some(handle) = task_executor.handle() {
        let pubkey = pubkey_bytes
            .decompress()
            .map_err(|e| format!("invalid pubkey, {:?}: {:?}", pubkey_bytes, e))?;

        match handle.block_on(initialized_validators.delete_definition_and_keystore(&pubkey, true))
        {
            Ok(_) => Ok(DeleteKeystoreStatus::Deleted),
            Err(e) => match e {
                Error::ValidatorNotInitialized(_) => Ok(DeleteKeystoreStatus::NotFound),
                _ => Err(format!("unable to disable and delete: {:?}", e)),
            },
        }
    } else {
        Err("validator client shutdown".into())
    }
}
