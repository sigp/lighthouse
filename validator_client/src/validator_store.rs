use crate::validator_directory::ValidatorDirectory;
use parking_lot::RwLock;
use slog::{error, Logger};
use std::collections::HashMap;
use std::fs::read_dir;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use tree_hash::{SignedRoot, TreeHash};
use types::{BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, PublicKey, Signature};

#[derive(Clone)]
pub struct ValidatorStore<E> {
    validators: Arc<RwLock<HashMap<PublicKey, ValidatorDirectory>>>,
    spec: Arc<ChainSpec>,
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
}
