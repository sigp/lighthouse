use crate::{config::Config, fork_service::ForkService};
use parking_lot::RwLock;
use rayon::prelude::*;
use slog::{error, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::fs::read_dir;
use std::marker::PhantomData;
use std::sync::Arc;
use tempdir::TempDir;
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey,
    SelectionProof, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};
use validator_dir::ValidatorDir;

#[derive(PartialEq)]
struct LocalValidator {
    validator_dir: ValidatorDir,
    voting_keypair: Keypair,
}

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<HashMap<PublicKey, LocalValidator>>>,
    genesis_validators_root: Hash256,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    fork_service: ForkService<T, E>,
    _phantom: PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn load_from_disk(
        config: &Config,
        genesis_validators_root: Hash256,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
        let validator_key_values = read_dir(&config.data_dir)
            .map_err(|e| {
                format!(
                    "Failed to read base directory {:?}: {:?}",
                    config.data_dir, e
                )
            })?
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter_map(|validator_dir| {
                let path = validator_dir.ok()?.path();

                if path.is_dir() {
                    match ValidatorDir::open(path.clone()) {
                        Ok(validator_dir) => {
                            match validator_dir.voting_keypair(&config.secrets_dir) {
                                Ok(voting_keypair) => Some(LocalValidator {
                                    validator_dir,
                                    voting_keypair,
                                }),
                                Err(e) => {
                                    error!(
                                        log,
                                        "Failed to load a validator keypair";
                                        "error" => format!("{:?}", e),
                                        "path" => path.to_str(),
                                    );
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                log,
                                "Failed to load a validator directory";
                                "error" => format!("{:?}", e),
                                "path" => path.to_str(),
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .map(|local_validator| (local_validator.voting_keypair.pk.clone(), local_validator));

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_par_iter(validator_key_values))),
            genesis_validators_root,
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            fork_service,
            _phantom: PhantomData,
        })
    }

    pub fn voting_pubkeys(&self) -> Vec<PublicKey> {
        self.validators
            .read()
            .iter()
            .map(|(pubkey, _dir)| pubkey.clone())
            .collect()
    }

    pub fn num_voting_validators(&self) -> usize {
        self.validators.read().len()
    }

    fn fork(&self) -> Option<Fork> {
        if self.fork_service.fork().is_none() {
            error!(
                self.log,
                "Unable to get Fork for signing";
            );
        }
        self.fork_service.fork()
    }

    pub fn randao_reveal(&self, validator_pubkey: &PublicKey, epoch: Epoch) -> Option<Signature> {
        // TODO: check this against the slot clock to make sure it's not an early reveal?
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|local_validator| {
                let voting_keypair = &local_validator.voting_keypair;
                let domain = self.spec.get_domain(
                    epoch,
                    Domain::Randao,
                    &self.fork()?,
                    self.genesis_validators_root,
                );
                let message = epoch.signing_root(domain);

                Some(Signature::new(message.as_bytes(), &voting_keypair.sk))
            })
    }

    pub fn sign_block(
        &self,
        validator_pubkey: &PublicKey,
        block: BeaconBlock<E>,
    ) -> Option<SignedBeaconBlock<E>> {
        // TODO: check for slashing.
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|local_validator| {
                let voting_keypair = &local_validator.voting_keypair;
                Some(block.sign(
                    &voting_keypair.sk,
                    &self.fork()?,
                    self.genesis_validators_root,
                    &self.spec,
                ))
            })
    }

    pub fn sign_attestation(
        &self,
        validator_pubkey: &PublicKey,
        validator_committee_position: usize,
        attestation: &mut Attestation<E>,
    ) -> Option<()> {
        // TODO: check for slashing.
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|local_validator| {
                let voting_keypair = &local_validator.voting_keypair;

                attestation
                    .sign(
                        &voting_keypair.sk,
                        validator_committee_position,
                        &self.fork()?,
                        self.genesis_validators_root,
                        &self.spec,
                    )
                    .map_err(|e| {
                        error!(
                            self.log,
                            "Error whilst signing attestation";
                            "error" => format!("{:?}", e)
                        )
                    })
                    .ok()?;

                Some(())
            })
    }

    /// Signs an `AggregateAndProof` for a given validator.
    ///
    /// The resulting `SignedAggregateAndProof` is sent on the aggregation channel and cannot be
    /// modified by actors other than the signing validator.
    pub fn produce_signed_aggregate_and_proof(
        &self,
        validator_pubkey: &PublicKey,
        validator_index: u64,
        aggregate: Attestation<E>,
        selection_proof: SelectionProof,
    ) -> Option<SignedAggregateAndProof<E>> {
        let validators = self.validators.read();
        let voting_keypair = &validators.get(validator_pubkey)?.voting_keypair;

        Some(SignedAggregateAndProof::from_aggregate(
            validator_index,
            aggregate,
            Some(selection_proof),
            &voting_keypair.sk,
            &self.fork()?,
            self.genesis_validators_root,
            &self.spec,
        ))
    }

    /// Produces a `SelectionProof` for the `slot`, signed by with corresponding secret key to
    /// `validator_pubkey`.
    pub fn produce_selection_proof(
        &self,
        validator_pubkey: &PublicKey,
        slot: Slot,
    ) -> Option<SelectionProof> {
        let validators = self.validators.read();
        let voting_keypair = &validators.get(validator_pubkey)?.voting_keypair;

        Some(SelectionProof::new::<E>(
            slot,
            &voting_keypair.sk,
            &self.fork()?,
            self.genesis_validators_root,
            &self.spec,
        ))
    }
}
