mod builder_definitions;
use builder_definitions::BuilderConfigFile;
pub use builder_definitions::{BuilderDefinition, Error};
use builder_types::{
    BuilderConfig, BuilderEntry, BuilderPubkeys, RequestAuthData, SignedRequestAuth,
};
use parking_lot::RwLock;
use ssz_types::VariableList;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::error;

#[derive(Clone)]
pub struct BuilderStore {
    config: Arc<RwLock<BuilderConfigFile>>,
    validators_dir: PathBuf,
}

impl BuilderStore {
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let validators_dir = validators_dir.as_ref().to_path_buf();

        Ok(Self {
            config: Arc::new(RwLock::new(BuilderConfigFile::open_or_create(
                &validators_dir,
            )?)),
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
    /// config always carries the global policy; its `builders` list holds only the successfully
    /// signed builders, and is empty when no builders are enabled or every one failed to sign.
    pub async fn builder_config<F, Fut, E>(&self, sign: F) -> BuilderConfig
    where
        F: Fn(RequestAuthData) -> Fut,
        Fut: Future<Output = Result<SignedRequestAuth, E>>,
        E: std::fmt::Debug,
    {
        // Snapshot the enabled builders and the global policy under the lock, then sign outside it,
        // so the lock is never held across an `.await`.
        let (definitions, min_bid, builder_boost_factor) = {
            let config = self.config.read();
            let definitions: Vec<BuilderDefinition> = config
                .as_slice()
                .iter()
                .filter(|d| d.enabled)
                .cloned()
                .collect();
            (definitions, config.min_bid, config.builder_boost_factor)
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
        let mut config = self.config.write();
        // Validate a candidate copy before committing, so a bad insert leaves the config unchanged
        // (and the global bid-policy defaults are preserved).
        let mut candidate = config.clone();
        candidate.push(builder);
        candidate.validate()?;

        *config = candidate;
        config.save(&self.validators_dir)
    }
}
