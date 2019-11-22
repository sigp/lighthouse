use crate::validator_directory::{ValidatorDirectory, ValidatorDirectoryBuilder};
use parking_lot::RwLock;
use rayon::prelude::*;
use slog::{error, Logger};
use std::collections::HashMap;
use std::fs::read_dir;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use tempdir::TempDir;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, PublicKey, Signature,
};

#[derive(Clone)]
pub struct ValidatorStore<E> {
    validators: Arc<RwLock<HashMap<PublicKey, ValidatorDirectory>>>,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> ValidatorStore<E> {
    pub fn load_from_disk(base_dir: PathBuf, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let validator_iter = read_dir(&base_dir)
            .map_err(|e| format!("Failed to read base directory: {:?}", e))?
            .filter_map(|validator_dir| {
                let path = validator_dir.ok()?.path();

                if path.is_dir() {
                    match ValidatorDirectory::load_for_signing(path.clone()) {
                        Ok(validator_directory) => Some(validator_directory),
                        Err(e) => {
                            error!(
                                log,
                                "Failed to load a validator directory";
                                "error" => e,
                                "path" => path.to_str(),
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .filter_map(|validator_directory| {
                validator_directory
                    .voting_keypair
                    .clone()
                    .map(|voting_keypair| (voting_keypair.pk, validator_directory))
            });

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validator_iter))),
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            _phantom: PhantomData,
        })
    }

    pub fn insecure_ephemeral_validators(
        range: Range<usize>,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, String> {
        let temp_dir = TempDir::new("insecure_validator")
            .map_err(|e| format!("Unable to create temp dir: {:?}", e))?;
        let data_dir = PathBuf::from(temp_dir.path());

        let validators = range
            .collect::<Vec<_>>()
            .par_iter()
            .map(|index| {
                ValidatorDirectoryBuilder::default()
                    .spec(spec.clone())
                    .full_deposit_amount()?
                    .insecure_keypairs(*index)
                    .create_directory(data_dir.clone())?
                    .write_keypair_files()?
                    .write_eth1_data_file()?
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|validator_directory| {
                validator_directory
                    .voting_keypair
                    .clone()
                    .map(|voting_keypair| (voting_keypair.pk, validator_directory))
            });

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validators))),
            spec: Arc::new(spec),
            log,
            temp_dir: Some(Arc::new(temp_dir)),
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

    pub fn randao_reveal(
        &self,
        validator_pubkey: &PublicKey,
        epoch: Epoch,
        fork: &Fork,
    ) -> Option<Signature> {
        // TODO: check this against the slot clock to make sure it's not an early reveal?
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|validator_dir| {
                validator_dir.voting_keypair.as_ref().map(|voting_keypair| {
                    let message = epoch.tree_hash_root();
                    let domain = self.spec.get_domain(epoch, Domain::Randao, &fork);
                    Signature::new(&message, domain, &voting_keypair.sk)
                })
            })
    }

    pub fn sign_block(
        &self,
        validator_pubkey: &PublicKey,
        mut block: BeaconBlock<E>,
        fork: &Fork,
    ) -> Option<BeaconBlock<E>> {
        // TODO: check for slashing.
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|validator_dir| {
                validator_dir.voting_keypair.as_ref().map(|voting_keypair| {
                    let epoch = block.slot.epoch(E::slots_per_epoch());
                    let message = block.signed_root();
                    let domain = self.spec.get_domain(epoch, Domain::BeaconProposer, &fork);
                    block.signature = Signature::new(&message, domain, &voting_keypair.sk);
                    block
                })
            })
    }

    pub fn sign_attestation(
        &self,
        validator_pubkey: &PublicKey,
        validator_committee_position: usize,
        mut attestation: Attestation<E>,
        fork: &Fork,
    ) -> Option<Attestation<E>> {
        // TODO: check for slashing.
        self.validators
            .read()
            .get(validator_pubkey)
            .and_then(|validator_dir| {
                validator_dir
                    .voting_keypair
                    .as_ref()
                    .and_then(|voting_keypair| {
                        attestation
                            .sign(
                                &voting_keypair.sk,
                                validator_committee_position,
                                fork,
                                &self.spec,
                            )
                            .map_err(|e| {
                                error!(
                                    self.log,
                                    "Error whilst signing attestation";
                                    "error" => format!("{:?}", e)
                                )
                            })
                            .map(|()| attestation)
                            .ok()
                    })
            })
    }
}
