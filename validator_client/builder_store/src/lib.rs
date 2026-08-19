mod builder_definitions;
use builder_definitions::BuilderConfigFile;
pub use builder_definitions::{
    BuilderDefinition, Error, ResolvedBuilderConfig, ValidatorBuilderConfig,
    ValidatorBuilderDefinition,
};
use builder_types::{
    BuilderConfig, BuilderEntry, BuilderPubkeys, RequestAuthData, SignedRequestAuth,
};
use parking_lot::{Mutex, RwLock};
use ssz_types::VariableList;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::error;

#[derive(Clone)]
pub struct BuilderStore {
    config: Arc<RwLock<BuilderConfigFile>>,
    update_lock: Arc<Mutex<()>>,
    validators_dir: PathBuf,
}

impl BuilderStore {
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let validators_dir = validators_dir.as_ref().to_path_buf();

        Ok(Self {
            config: Arc::new(RwLock::new(BuilderConfigFile::open_or_create(
                &validators_dir,
            )?)),
            update_lock: Arc::new(Mutex::new(())),
            validators_dir,
        })
    }

    /// Resolve the enabled builders into a wire [`BuilderConfig`], signing each builder's request
    /// auth via `sign`.
    ///
    /// Per-builder `min_bid`/`builder_boost_factor` inherit the global defaults when unset, and each
    /// builder's `auth_data` defaults to the UTF-8 bytes of its URL when unset. `sign` receives a
    /// builder's opaque auth `data` and returns the corresponding `SignedRequestAuth` — in
    /// practice signed for the current proposer/slot and cached.
    ///
    /// Signing is per-builder: a builder whose auth `sign` fails to produce is logged (with the
    /// returned error) and omitted, so one unsignable builder cannot drop the rest. The returned
    /// config always carries the validator's resolved policy; its `builders` list holds only the
    /// successfully signed builders, and is empty when no builders are enabled or every one
    /// failed to sign.
    pub async fn builder_config<F, Fut, E>(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
        sign: F,
    ) -> BuilderConfig
    where
        F: Fn(RequestAuthData) -> Fut,
        Fut: Future<Output = Result<SignedRequestAuth, E>>,
        E: std::fmt::Debug,
    {
        // Snapshot the validator's resolved builders and policy under the lock, then sign outside
        // it, so the lock is never held across an `.await`.
        let (definitions, min_bid, builder_boost_factor) = {
            let config = self.config.read();
            let resolved = config.resolved_for(validator_pubkey);
            (
                resolved.builders,
                resolved.min_bid,
                resolved.builder_boost_factor,
            )
        };

        // Sign every builder's request auth concurrently. With a remote signer each `sign` is a
        // network round trip, and the signatures are independent, so signing in sequence would put
        // up to `MaxBuilderEntries` serial round trips on the block-production critical path.
        let signed = futures::future::join_all(definitions.into_iter().filter_map(|definition| {
            let auth_data = definition
                .auth_data
                .clone()
                .unwrap_or_else(|| definition.url.to_default_auth_data());
            // A zero-length auth `data` is invalid on the wire (beacon-specs #165 / beacon-APIs
            // #630); the beacon node would reject the whole request body, so drop the builder here.
            if auth_data.is_empty() {
                error!(
                    builder_url = %definition.url,
                    "Zero-length auth_data is invalid; omitting builder from config"
                );
                return None;
            }
            let signing = sign(auth_data);
            Some(async move { (definition, signing.await) })
        }))
        .await;

        // `join_all` preserves input order, so `builders` keeps the configured order. Omit any
        // builder we cannot sign for, logging the error, rather than failing the whole config.
        let mut builders = Vec::with_capacity(signed.len());
        for (definition, result) in signed {
            let auth = match result {
                Ok(auth) => auth,
                Err(e) => {
                    error!(
                        error = ?e,
                        builder_url = %definition.url,
                        "Failed to sign builder request auth; omitting builder from config"
                    );
                    continue;
                }
            };
            let Ok(builder_pubkeys) = BuilderPubkeys::new(definition.builder_pubkeys) else {
                error!(
                    builder_url = %definition.url,
                    "Too many builder pubkeys; omitting builder from config"
                );
                continue;
            };
            builders.push(BuilderEntry {
                url: definition.url,
                auth,
                builder_pubkeys,
                max_execution_payment: definition.max_execution_payment,
                min_bid: definition.min_bid.unwrap_or(min_bid),
                builder_boost_factor: definition
                    .builder_boost_factor
                    .unwrap_or(builder_boost_factor),
            });
        }

        BuilderConfig {
            // The number of builders is bounded by `MaxBuilderEntries` at config load, so this
            // cannot overflow.
            builders: VariableList::new(builders)
                .expect("builder count is bounded by MaxBuilderEntries at config load"),
            min_bid,
            builder_boost_factor,
        }
    }

    pub fn insert(&self, builder: BuilderDefinition) -> Result<(), Error> {
        let _update_guard = self.update_lock.lock();
        let mut config = self.config.write();
        // Validate a candidate copy before committing, so a bad insert leaves the config unchanged
        // (and the global bid-policy defaults are preserved).
        let mut candidate = config.clone();
        candidate.push(builder);
        candidate.validate()?;

        *config = candidate;
        config.save(&self.validators_dir)
    }

    /// Return the fully resolved configuration for a validator without signing builder auth data.
    pub fn validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
    ) -> ResolvedBuilderConfig {
        self.config.read().resolved_for(validator_pubkey)
    }

    /// Replace the per-validator configuration and persist it atomically.
    pub fn set_validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
        validator_config: ValidatorBuilderConfig,
    ) -> Result<(), Error> {
        validator_config.validate()?;

        let _update_guard = self.update_lock.lock();
        let mut candidate = self.config.read().clone();
        candidate
            .validator_configs
            .insert(validator_pubkey.to_string(), validator_config);
        candidate.save(&self.validators_dir)?;
        *self.config.write() = candidate;
        Ok(())
    }

    /// Remove a validator's override and persist the inherited global configuration atomically.
    pub fn delete_validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
    ) -> Result<(), Error> {
        let _update_guard = self.update_lock.lock();
        let mut candidate = self.config.read().clone();
        if candidate
            .validator_configs
            .remove(&validator_pubkey.to_string())
            .is_none()
        {
            return Ok(());
        }
        candidate.save(&self.validators_dir)?;
        *self.config.write() = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Keypair;
    use builder_types::RequestAuth;
    use tempfile::tempdir;
    use types::Slot;

    fn global_builder(url: &str, max_execution_payment: u64) -> BuilderDefinition {
        BuilderDefinition {
            enabled: true,
            url: url.parse().unwrap(),
            auth_data: None,
            builder_pubkeys: vec![],
            max_execution_payment,
            min_bid: None,
            builder_boost_factor: None,
        }
    }

    fn validator_builder(url: &str) -> ValidatorBuilderDefinition {
        ValidatorBuilderDefinition {
            url: url.parse().unwrap(),
            auth_data: None,
            builder_pubkeys: vec![],
            max_execution_payment: None,
            min_bid: None,
            builder_boost_factor: None,
        }
    }

    fn signed_auth(data: RequestAuthData) -> SignedRequestAuth {
        SignedRequestAuth {
            message: RequestAuth {
                data,
                slot: Slot::new(0),
            },
            signature: bls::Signature::empty(),
        }
    }

    #[test]
    fn validator_config_inherits_global_and_distinguishes_empty_builders() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();

        store
            .insert(global_builder("https://global-builder.example", 7))
            .unwrap();
        let mut empty_auth = global_builder("https://empty-auth.example", 7);
        empty_auth.auth_data = Some(RequestAuthData::default());
        store.insert(empty_auth).unwrap();
        let mut excessive_pubkeys = global_builder("https://too-many-pubkeys.example", 7);
        excessive_pubkeys.builder_pubkeys =
            (0..65).map(|_| Keypair::random().pk.compress()).collect();
        store.insert(excessive_pubkeys).unwrap();
        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    min_bid: Some(5),
                    builder_boost_factor: Some(125),
                    builders: None,
                },
            )
            .unwrap();

        let inherited = store.validator_config(&validator);
        assert_eq!(inherited.min_bid, 5);
        assert_eq!(inherited.builder_boost_factor, 125);
        assert_eq!(inherited.builders.len(), 1);
        assert_eq!(inherited.builders[0].max_execution_payment, 7);
        assert_eq!(inherited.builders[0].min_bid, Some(5));
        assert_eq!(inherited.builders[0].builder_boost_factor, Some(125));

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    min_bid: None,
                    builder_boost_factor: None,
                    builders: Some(vec![]),
                },
            )
            .unwrap();
        assert!(store.validator_config(&validator).builders.is_empty());

        store.delete_validator_config(&validator).unwrap();
        let restored = store.validator_config(&validator);
        assert_eq!(restored.min_bid, 0);
        assert_eq!(restored.builder_boost_factor, 100);
        assert_eq!(restored.builders.len(), 1);
    }

    #[test]
    fn empty_validator_config_persists_across_store_restart() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();

        store
            .set_validator_config(&validator, ValidatorBuilderConfig::default())
            .unwrap();

        let file = builder_definitions::BuilderConfigFile::open(directory.path()).unwrap();
        assert!(file.validator_configs.contains_key(&validator.to_string()));

        let restarted = BuilderStore::open_or_create(directory.path()).unwrap();
        assert_eq!(
            restarted.validator_config(&validator),
            store.validator_config(&validator)
        );

        restarted.delete_validator_config(&validator).unwrap();
        let file = builder_definitions::BuilderConfigFile::open(directory.path()).unwrap();
        assert!(!file.validator_configs.contains_key(&validator.to_string()));
    }

    #[test]
    fn validator_updates_are_serialized_without_losing_each_other() {
        let directory = tempdir().unwrap();
        let store = Arc::new(BuilderStore::open_or_create(directory.path()).unwrap());
        let first = Keypair::random().pk.compress();
        let second = Keypair::random().pk.compress();

        let handles = [(first, 11), (second, 22)].map(|(validator, min_bid)| {
            let store = store.clone();
            std::thread::spawn(move || {
                store.set_validator_config(
                    &validator,
                    ValidatorBuilderConfig {
                        min_bid: Some(min_bid),
                        ..Default::default()
                    },
                )
            })
        });
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(store.validator_config(&first).min_bid, 11);
        assert_eq!(store.validator_config(&second).min_bid, 22);

        let restarted = BuilderStore::open_or_create(directory.path()).unwrap();
        assert_eq!(restarted.validator_config(&first).min_bid, 11);
        assert_eq!(restarted.validator_config(&second).min_bid, 22);
    }

    #[test]
    fn builder_consumer_observes_runtime_updates_immediately() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();
        store
            .insert(global_builder("https://global-builder.example", 7))
            .unwrap();

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    builders: Some(vec![]),
                    ..Default::default()
                },
            )
            .unwrap();
        let empty =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert!(empty.builders.is_empty());

        store.delete_validator_config(&validator).unwrap();
        let inherited =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert_eq!(inherited.builders.len(), 1);
        assert_eq!(inherited.builders[0].max_execution_payment, 7);
    }

    #[test]
    fn custom_builders_resolve_payment_limits_from_enabled_globals() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();
        store
            .insert(global_builder("https://global-builder.example", 9))
            .unwrap();
        store
            .insert(BuilderDefinition {
                enabled: false,
                url: "https://disabled-builder.example".parse().unwrap(),
                auth_data: None,
                builder_pubkeys: vec![],
                max_execution_payment: 9,
                min_bid: None,
                builder_boost_factor: None,
            })
            .unwrap();

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    builders: Some(vec![
                        validator_builder("https://global-builder.example"),
                        validator_builder("https://disabled-builder.example"),
                    ]),
                    ..Default::default()
                },
            )
            .unwrap();

        let resolved = store.validator_config(&validator);
        assert_eq!(resolved.builders[0].max_execution_payment, 9);
        assert_eq!(resolved.builders[1].max_execution_payment, 0);
    }
}
