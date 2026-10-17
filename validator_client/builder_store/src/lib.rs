mod builder_definitions;
use builder_definitions::BuilderConfigFile;
pub use builder_definitions::{
    BuilderDefinition, Error, ResolvedBuilderConfig, ValidatorBuilderConfig,
    ValidatorBuilderDefinition,
};
use builder_types::{
    BuilderConfig, BuilderEntry, BuilderPubkeys, RequestAuthData, SignedRequestAuth,
};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use serde::{Deserialize, Serialize};
use ssz_types::VariableList;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::error;

/// Process-wide defaults for the global builder configuration, supplied by the CLI.
///
/// These are never persisted and only apply when the corresponding file setting is omitted.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Fallback global minimum total payment in gwei.
    pub min_bid: Option<u64>,
    /// Fallback global builder boost factor.
    pub builder_boost_factor: Option<u64>,
    /// Fallback global builder list.
    pub builders: Option<Vec<BuilderDefinition>>,
}

impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        BuilderConfigFile {
            builders: self.builders.clone(),
            ..Default::default()
        }
        .validate()
    }
}

#[derive(Clone)]
pub struct BuilderStore {
    config: Arc<RwLock<BuilderConfigFile>>,
    cli_config: Arc<Config>,
    validators_dir: PathBuf,
}

impl BuilderStore {
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        Self::open_or_create_with_config(validators_dir, Config::default())
    }

    pub fn open_or_create_with_config<P: AsRef<Path>>(
        validators_dir: P,
        cli_config: Config,
    ) -> Result<Self, Error> {
        cli_config.validate()?;
        let validators_dir = validators_dir.as_ref().to_path_buf();

        Ok(Self {
            config: Arc::new(RwLock::new(BuilderConfigFile::open_or_create(
                &validators_dir,
            )?)),
            cli_config: Arc::new(cli_config),
            validators_dir,
        })
    }

    /// Resolve the enabled builders into a wire [`BuilderConfig`], signing each builder's request
    /// auth via `sign`.
    ///
    /// Per-builder `min_bid`/`builder_boost_factor` inherit the global defaults when unset, and each
    /// builder's `auth_data` defaults to its lowercase ASCII hostname when unset. `sign` receives a
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
            let resolved = config.resolved_for(validator_pubkey, &self.cli_config);
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
            let auth_data = match definition
                .auth_data
                .clone()
                .map(Ok)
                .unwrap_or_else(|| definition.url.to_default_auth_data())
            {
                Ok(data) => data,
                Err(error) => {
                    error!(
                        error = ?error,
                        builder_url = %definition.url,
                        "Failed to derive builder auth_data; omitting builder from config"
                    );
                    return None;
                }
            };
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
        self.persist_update(|candidate| {
            candidate.push(builder);
            candidate.validate()?;
            Ok(true)
        })
    }

    /// Return the fully resolved configuration for a validator without signing builder auth data.
    pub fn get_validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
    ) -> ResolvedBuilderConfig {
        self.config
            .read()
            .resolved_for(validator_pubkey, &self.cli_config)
    }

    /// Replace the per-validator configuration and persist it atomically.
    pub fn set_validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
        validator_config: ValidatorBuilderConfig,
    ) -> Result<(), Error> {
        validator_config.validate()?;

        self.persist_update(|candidate| {
            candidate
                .validator_configs
                .insert(validator_pubkey.to_string(), validator_config);
            Ok(true)
        })
    }

    /// Remove a validator's override and persist the inherited global configuration atomically.
    pub fn delete_validator_config(
        &self,
        validator_pubkey: &bls::PublicKeyBytes,
    ) -> Result<(), Error> {
        self.persist_update(|candidate| {
            Ok(candidate
                .validator_configs
                .remove(&validator_pubkey.to_string())
                .is_some())
        })
    }

    /// Apply and persist one update while ordinary readers continue using the current config.
    ///
    /// The update returns `false` when it made no change and no save is required.
    /// The upgradable read guard serializes writers from snapshot through save. The brief upgrade
    /// publishes only a successfully persisted candidate.
    fn persist_update(
        &self,
        update: impl FnOnce(&mut BuilderConfigFile) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let config = self.config.upgradable_read();
        let mut candidate = config.clone();
        let changed = update(&mut candidate)?;
        if !changed {
            return Ok(());
        }
        candidate.save(&self.validators_dir)?;
        *RwLockUpgradableReadGuard::upgrade(config) = candidate;
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
    fn file_globals_take_precedence_over_cli_and_survive_validator_updates() {
        let directory = tempdir().unwrap();
        let validator = Keypair::random().pk.compress();
        let mut file_builder = global_builder("https://file-builder.example", 7);
        file_builder.auth_data = Some(RequestAuthData::new(b"file-auth".to_vec()).unwrap());
        file_builder.builder_pubkeys = vec![Keypair::random().pk.compress()];
        let file = BuilderConfigFile {
            min_bid: Some(5),
            builder_boost_factor: Some(90),
            builders: Some(vec![file_builder]),
            ..Default::default()
        };
        file.save(directory.path()).unwrap();

        let cli_config = Config {
            min_bid: Some(10),
            builder_boost_factor: Some(125),
            builders: Some(vec![
                global_builder("https://cli-builder.example", 20),
                global_builder("https://file-builder.example", 20),
            ]),
        };
        let store =
            BuilderStore::open_or_create_with_config(directory.path(), cli_config.clone()).unwrap();
        let inherited = store.get_validator_config(&validator);
        assert_eq!(inherited.min_bid, 5);
        assert_eq!(inherited.builder_boost_factor, 90);
        assert_eq!(inherited.builders.len(), 1);
        assert_eq!(
            inherited.builders[0].url,
            file.builders.as_ref().unwrap()[0].url
        );
        assert_eq!(inherited.builders[0].max_execution_payment, 7);
        assert_eq!(
            inherited.builders[0].auth_data,
            file.builders.as_ref().unwrap()[0].auth_data
        );
        assert_eq!(
            inherited.builders[0].builder_pubkeys,
            file.builders.as_ref().unwrap()[0].builder_pubkeys
        );

        let signed =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert_eq!(signed.min_bid, 5);
        assert_eq!(signed.builder_boost_factor, 90);
        assert_eq!(signed.builders.len(), 1);
        assert_eq!(signed.builders[0].url, inherited.builders[0].url);
        assert_eq!(signed.builders[0].max_execution_payment, 7);
        assert_eq!(&*signed.builders[0].auth.message.data, b"file-auth");

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    min_bid: Some(3),
                    builder_boost_factor: Some(80),
                    builders: None,
                },
            )
            .unwrap();
        let overridden = store.get_validator_config(&validator);
        assert_eq!(overridden.min_bid, 3);
        assert_eq!(overridden.builder_boost_factor, 80);
        assert_eq!(overridden.builders[0].min_bid, Some(3));
        assert_eq!(overridden.builders[0].builder_boost_factor, Some(80));

        let saved = BuilderConfigFile::open(directory.path()).unwrap();
        assert_eq!(saved.min_bid, file.min_bid);
        assert_eq!(saved.builder_boost_factor, file.builder_boost_factor);
        assert_eq!(saved.builders, file.builders);

        let restarted =
            BuilderStore::open_or_create_with_config(directory.path(), cli_config).unwrap();
        assert_eq!(restarted.get_validator_config(&validator), overridden);
        restarted.delete_validator_config(&validator).unwrap();
        assert_eq!(restarted.get_validator_config(&validator), inherited);

        let without_flags = BuilderStore::open_or_create(directory.path()).unwrap();
        let restored = without_flags.get_validator_config(&validator);
        assert_eq!(restored.min_bid, file.min_bid.unwrap());
        assert_eq!(
            restored.builder_boost_factor,
            file.builder_boost_factor.unwrap()
        );
        assert_eq!(
            restored.builders[0].url,
            file.builders.as_ref().unwrap()[0].url
        );
        assert_eq!(restored.builders[0].max_execution_payment, 7);
    }

    #[test]
    fn cli_defaults_fill_only_omitted_file_globals() {
        let validator = Keypair::random().pk.compress();
        let cli_config = Config {
            min_bid: Some(10),
            builder_boost_factor: Some(125),
            builders: Some(vec![global_builder("https://cli-builder.example", 20)]),
        };

        for (yaml, min_bid, builder_boost_factor, uses_cli_builders) in [
            ("{}", 10, 125, true),
            ("min_bid: 0\n", 0, 125, true),
            ("builder_boost_factor: 100\n", 10, 100, true),
            ("min_bid: 0\nbuilder_boost_factor: 0\n", 0, 0, true),
            ("min_bid: 7\n", 7, 125, true),
            ("builder_boost_factor: 90\n", 10, 90, true),
            ("builders: []\n", 10, 125, false),
            (
                "builders:\n  - enabled: false\n    url: https://disabled-builder.example\n    max_execution_payment: 7\n",
                10,
                125,
                false,
            ),
            (
                "min_bid: 0\nbuilder_boost_factor: 100\nbuilders: []\n",
                0,
                100,
                false,
            ),
        ] {
            let directory = tempdir().unwrap();
            std::fs::write(
                directory
                    .path()
                    .join(builder_definitions::BUILDERS_FILENAME),
                yaml,
            )
            .unwrap();
            let store =
                BuilderStore::open_or_create_with_config(directory.path(), cli_config.clone())
                    .unwrap();
            let resolved = store.get_validator_config(&validator);
            assert_eq!(resolved.min_bid, min_bid, "{yaml}");
            assert_eq!(
                resolved.builder_boost_factor, builder_boost_factor,
                "{yaml}"
            );
            if uses_cli_builders {
                assert_eq!(resolved.builders.len(), 1, "{yaml}");
                assert_eq!(
                    resolved.builders[0].url.as_str().unwrap(),
                    "https://cli-builder.example"
                );
                assert_eq!(resolved.builders[0].max_execution_payment, 20);
                assert_eq!(resolved.builders[0].min_bid, Some(min_bid));
                assert_eq!(
                    resolved.builders[0].builder_boost_factor,
                    Some(builder_boost_factor)
                );
            } else {
                assert!(resolved.builders.is_empty(), "{yaml}");
            }
        }
    }

    #[test]
    fn cli_defaults_are_not_persisted_when_file_globals_are_omitted() {
        let directory = tempdir().unwrap();
        let validator = Keypair::random().pk.compress();
        let cli_config = Config {
            min_bid: Some(10),
            builder_boost_factor: Some(125),
            builders: Some(vec![global_builder("https://cli-builder.example", 20)]),
        };
        let store =
            BuilderStore::open_or_create_with_config(directory.path(), cli_config.clone()).unwrap();
        let inherited = store.get_validator_config(&validator);
        assert_eq!(inherited.min_bid, 10);
        assert_eq!(inherited.builder_boost_factor, 125);
        assert_eq!(inherited.builders.len(), 1);

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    min_bid: Some(0),
                    builder_boost_factor: Some(0),
                    builders: Some(vec![]),
                },
            )
            .unwrap();
        let saved = BuilderConfigFile::open(directory.path()).unwrap();
        assert!(saved.min_bid.is_none());
        assert!(saved.builder_boost_factor.is_none());
        assert!(saved.builders.is_none());

        let restarted =
            BuilderStore::open_or_create_with_config(directory.path(), cli_config).unwrap();
        let overridden = restarted.get_validator_config(&validator);
        assert_eq!(overridden.min_bid, 0);
        assert_eq!(overridden.builder_boost_factor, 0);
        assert!(overridden.builders.is_empty());
        restarted.delete_validator_config(&validator).unwrap();
        assert_eq!(restarted.get_validator_config(&validator), inherited);

        let saved = BuilderConfigFile::open(directory.path()).unwrap();
        assert!(saved.min_bid.is_none());
        assert!(saved.builder_boost_factor.is_none());
        assert!(saved.builders.is_none());
        let without_flags = BuilderStore::open_or_create(directory.path()).unwrap();
        let restored = without_flags.get_validator_config(&validator);
        assert_eq!(restored.min_bid, 0);
        assert_eq!(restored.builder_boost_factor, 100);
        assert!(restored.builders.is_empty());
    }

    #[test]
    fn validator_builders_inherit_payment_from_file_before_cli_defaults() {
        let directory = tempdir().unwrap();
        let validator = Keypair::random().pk.compress();
        let url = "https://builder.example";
        BuilderConfigFile {
            builders: Some(vec![global_builder(url, 7)]),
            ..Default::default()
        }
        .save(directory.path())
        .unwrap();
        let store = BuilderStore::open_or_create_with_config(
            directory.path(),
            Config {
                builders: Some(vec![
                    global_builder(url, 20),
                    global_builder("https://cli-only.example", 30),
                ]),
                ..Default::default()
            },
        )
        .unwrap();
        let mut different_auth = validator_builder(url);
        different_auth.auth_data = Some(RequestAuthData::new(b"validator-auth".to_vec()).unwrap());
        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    builders: Some(vec![
                        validator_builder(url),
                        validator_builder("https://cli-only.example"),
                        different_auth,
                    ]),
                    ..Default::default()
                },
            )
            .unwrap();
        let resolved = store.get_validator_config(&validator);
        assert_eq!(resolved.builders[0].max_execution_payment, 7);
        assert_eq!(resolved.builders[1].max_execution_payment, 0);
        assert_eq!(resolved.builders[2].max_execution_payment, 0);
    }

    #[test]
    fn validator_builders_inherit_cli_execution_payment_by_url_and_auth() {
        let directory = tempdir().unwrap();
        let validator = Keypair::random().pk.compress();
        let url = "https://cli-builder.example";
        let store = BuilderStore::open_or_create_with_config(
            directory.path(),
            Config {
                min_bid: Some(10),
                builder_boost_factor: Some(125),
                builders: Some(vec![global_builder(url, 20)]),
            },
        )
        .unwrap();

        let signed =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert_eq!(signed.min_bid, 10);
        assert_eq!(signed.builder_boost_factor, 125);
        assert_eq!(signed.builders[0].min_bid, 10);
        assert_eq!(signed.builders[0].builder_boost_factor, 125);
        assert_eq!(signed.builders[0].max_execution_payment, 20);
        assert_eq!(
            &*signed.builders[0].auth.message.data,
            b"cli-builder.example"
        );

        for (auth_data, max_execution_payment, expected_payment) in [
            (None, None, 20),
            (Some(b"cli-builder.example".to_vec()), None, 20),
            (Some(b"validator-auth".to_vec()), None, 0),
            (None, Some(0), 0),
            (None, Some(30), 30),
        ] {
            let mut builder = validator_builder(url);
            builder.auth_data = auth_data.map(|data| RequestAuthData::new(data).unwrap());
            builder.max_execution_payment = max_execution_payment;
            store
                .set_validator_config(
                    &validator,
                    ValidatorBuilderConfig {
                        builders: Some(vec![builder]),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(
                store.get_validator_config(&validator).builders[0].max_execution_payment,
                expected_payment
            );
        }

        store
            .set_validator_config(
                &validator,
                ValidatorBuilderConfig {
                    builders: Some(vec![]),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(store.get_validator_config(&validator).builders.is_empty());
        store.delete_validator_config(&validator).unwrap();
        assert_eq!(store.get_validator_config(&validator).builders.len(), 1);
    }

    #[test]
    fn cli_policy_preserves_per_builder_overrides_in_file() {
        let directory = tempdir().unwrap();
        let validator = Keypair::random().pk.compress();
        let mut builder = global_builder("https://builder.example", 7);
        builder.min_bid = Some(15);
        builder.builder_boost_factor = Some(150);
        let file = BuilderConfigFile {
            builders: Some(vec![builder]),
            ..Default::default()
        };
        file.save(directory.path()).unwrap();

        let store = BuilderStore::open_or_create_with_config(
            directory.path(),
            Config {
                min_bid: Some(0),
                builder_boost_factor: Some(0),
                builders: None,
            },
        )
        .unwrap();
        let config = store.get_validator_config(&validator);
        assert_eq!(config.min_bid, 0);
        assert_eq!(config.builder_boost_factor, 0);
        assert_eq!(config.builders, file.builders.unwrap());
    }

    #[test]
    fn validator_config_inherits_global_and_distinguishes_empty_builders() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();

        let mut configured_global_builder = global_builder("https://global-builder.example", 7);
        configured_global_builder.min_bid = Some(100);
        configured_global_builder.builder_boost_factor = Some(200);
        store.insert(configured_global_builder).unwrap();
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

        let inherited = store.get_validator_config(&validator);
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
        assert!(store.get_validator_config(&validator).builders.is_empty());

        store.delete_validator_config(&validator).unwrap();
        let restored = store.get_validator_config(&validator);
        assert_eq!(restored.min_bid, 0);
        assert_eq!(restored.builder_boost_factor, 100);
        assert_eq!(restored.builders.len(), 1);
        assert_eq!(restored.builders[0].min_bid, Some(100));
        assert_eq!(restored.builders[0].builder_boost_factor, Some(200));
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
            restarted.get_validator_config(&validator),
            store.get_validator_config(&validator)
        );

        restarted.delete_validator_config(&validator).unwrap();
        let file = builder_definitions::BuilderConfigFile::open(directory.path()).unwrap();
        assert!(!file.validator_configs.contains_key(&validator.to_string()));
    }

    #[test]
    fn failed_insert_is_not_published() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();
        std::fs::create_dir(
            directory
                .path()
                .join(builder_definitions::BUILDERS_TEMP_FILENAME),
        )
        .unwrap();

        assert!(
            store
                .insert(global_builder("https://global-builder.example", 7))
                .is_err()
        );
        assert!(store.get_validator_config(&validator).builders.is_empty());
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
        assert_eq!(store.get_validator_config(&first).min_bid, 11);
        assert_eq!(store.get_validator_config(&second).min_bid, 22);

        let restarted = BuilderStore::open_or_create(directory.path()).unwrap();
        assert_eq!(restarted.get_validator_config(&first).min_bid, 11);
        assert_eq!(restarted.get_validator_config(&second).min_bid, 22);
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
    fn global_and_validator_auth_data_use_hostname_or_exact_override() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();
        let url = "HTTPS://Builder.Example:443/path?query#fragment";
        store.insert(global_builder(url, 9)).unwrap();

        let inherited =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert_eq!(
            &*inherited.builders[0].auth.message.data,
            b"builder.example"
        );
        assert_eq!(inherited.builders[0].url.as_str().unwrap(), url);

        for explicit in [
            None,
            Some(b"builder.example".to_vec()),
            Some(vec![0xff, 0x00, b'A']),
        ] {
            let expected = explicit
                .clone()
                .unwrap_or_else(|| b"builder.example".to_vec());
            let mut builder = validator_builder(url);
            builder.auth_data = explicit.map(|bytes| RequestAuthData::new(bytes).unwrap());
            store
                .set_validator_config(
                    &validator,
                    ValidatorBuilderConfig {
                        builders: Some(vec![builder]),
                        ..Default::default()
                    },
                )
                .unwrap();
            let config =
                futures::executor::block_on(store.builder_config(&validator, |data| async move {
                    Ok::<_, ()>(signed_auth(data))
                }));
            assert_eq!(&*config.builders[0].auth.message.data, expected.as_slice());
            assert_eq!(
                config.builders[0].max_execution_payment,
                if expected == b"builder.example" { 9 } else { 0 }
            );
        }
    }

    #[test]
    fn unicode_hostname_needs_explicit_auth_data() {
        let directory = tempdir().unwrap();
        let store = BuilderStore::open_or_create(directory.path()).unwrap();
        let validator = Keypair::random().pk.compress();
        let url = "https://bücher.example/";
        assert!(matches!(
            store.insert(global_builder(url, 9)),
            Err(Error::InvalidBuilderUrl(_))
        ));
        let mut config = ValidatorBuilderConfig {
            builders: Some(vec![validator_builder(url)]),
            ..Default::default()
        };
        assert!(matches!(
            store.set_validator_config(&validator, config.clone()),
            Err(Error::InvalidBuilderUrl(_))
        ));
        let explicit = RequestAuthData::new(vec![0xff, 0x00, b'A']).unwrap();
        let mut global = global_builder(url, 9);
        global.auth_data = Some(explicit.clone());
        store.insert(global).unwrap();
        config.builders.as_mut().unwrap()[0].auth_data = Some(explicit.clone());
        store.set_validator_config(&validator, config).unwrap();
        let signed =
            futures::executor::block_on(store.builder_config(&validator, |data| async move {
                Ok::<_, ()>(signed_auth(data))
            }));
        assert_eq!(signed.builders[0].auth.message.data, explicit);
        assert_eq!(signed.builders[0].max_execution_payment, 9);
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

        let resolved = store.get_validator_config(&validator);
        assert_eq!(resolved.builders[0].max_execution_payment, 9);
        assert_eq!(resolved.builders[1].max_execution_payment, 0);
    }
}
