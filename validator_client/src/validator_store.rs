use crate::fork_service::ForkService;
use crate::validator_directory::{ValidatorDirectory, ValidatorDirectoryBuilder};
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use slashing_protection::{
    signed_attestation::SignedAttestation,
    signed_block::SignedBlock,
    validator_history::{SlashingProtection as SlashingProtectionTrait, ValidatorHistory},
};
use slog::{error, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::read_dir;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;
use tempdir::TempDir;
use tree_hash::TreeHash;
use types::{
    Attestation, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Keypair, PublicKey,
    Signature,
};

struct VotingValidator {
    voting_keypair: Keypair,
    attestation_slashing_protection: Option<Arc<Mutex<ValidatorHistory<SignedAttestation>>>>,
    block_slashing_protection: Option<Arc<Mutex<ValidatorHistory<SignedBlock>>>>,
}

impl TryFrom<ValidatorDirectory> for VotingValidator {
    type Error = String;

    fn try_from(dir: ValidatorDirectory) -> Result<Self, Self::Error> {
        let slots_per_epoch = dir.slots_per_epoch;
        let attestation_slashing_protection = dir
            .attestation_slashing_protection
            .and_then(|path| ValidatorHistory::open(&path, slots_per_epoch).ok());
        let block_slashing_protection = dir
            .block_slashing_protection
            .and_then(|path| ValidatorHistory::open(&path, slots_per_epoch).ok());

        if attestation_slashing_protection.is_none() || block_slashing_protection.is_none() {
            return Err(
                "Validator cannot vote without attestation or block slashing protection"
                    .to_string(),
            );
        }

        Ok(Self {
            voting_keypair: dir
                .voting_keypair
                .ok_or_else(|| "Validator without voting keypair cannot vote".to_string())?,
            attestation_slashing_protection: attestation_slashing_protection
                .map(|v| Arc::new(Mutex::new(v))),
            block_slashing_protection: block_slashing_protection.map(|v| Arc::new(Mutex::new(v))),
        })
    }
}

#[derive(Clone)]
pub struct ValidatorStore<T, E: EthSpec> {
    validators: Arc<RwLock<HashMap<PublicKey, VotingValidator>>>,
    spec: Arc<ChainSpec>,
    log: Logger,
    temp_dir: Option<Arc<TempDir>>,
    fork_service: ForkService<T, E>,
    _phantom: PhantomData<E>,
}

impl<T: SlotClock + 'static, E: EthSpec> ValidatorStore<T, E> {
    pub fn load_from_disk(
        base_dir: PathBuf,
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
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
                match VotingValidator::try_from(validator_directory.clone()) {
                    Ok(voting_validator) => Some(voting_validator),
                    Err(e) => {
                        error!(

                            log,
                            "Unable to load validator from disk";
                            "error" => e,
                            "path" => format!("{:?}", validator_directory.directory)
                        );
                        None
                    }
                }
            })
            .map(|voting_validator| (voting_validator.voting_keypair.pk.clone(), voting_validator));

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validator_iter))),
            spec: Arc::new(spec),
            log,
            temp_dir: None,
            fork_service,
            _phantom: PhantomData,
        })
    }

    pub fn insecure_ephemeral_validators(
        validator_indices: &[usize],
        spec: ChainSpec,
        fork_service: ForkService<T, E>,
        log: Logger,
    ) -> Result<Self, String> {
        let temp_dir = TempDir::new("insecure_validator")
            .map_err(|e| format!("Unable to create temp dir: {:?}", e))?;
        let data_dir = PathBuf::from(temp_dir.path());

        let validators = validator_indices
            .par_iter()
            .map(|index| {
                ValidatorDirectoryBuilder::default()
                    .spec(spec.clone())
                    .full_deposit_amount()?
                    .insecure_keypairs(*index)
                    .create_directory(data_dir.clone())?
                    .write_keypair_files()?
                    .write_eth1_data_file()?
                    .create_sqlite_slashing_dbs()?
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|validator_directory| {
                match VotingValidator::try_from(validator_directory.clone()) {
                    Ok(voting_validator) => Some(voting_validator),
                    Err(e) => {
                        error!(

                            log,
                            "Unable to load insecure validator from disk";
                            "error" => e,
                            "path" => format!("{:?}", validator_directory.directory)
                        );
                        None
                    }
                }
            })
            .map(|voting_validator| (voting_validator.voting_keypair.pk.clone(), voting_validator));

        Ok(Self {
            validators: Arc::new(RwLock::new(HashMap::from_iter(validators))),
            spec: Arc::new(spec),
            log,
            temp_dir: Some(Arc::new(temp_dir)),
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
            .and_then(|validator_dir| {
                let voting_keypair = &validator_dir.voting_keypair;
                let message = epoch.tree_hash_root();
                let domain = self.spec.get_domain(epoch, Domain::Randao, &self.fork()?);

                Some(Signature::new(&message, domain, &voting_keypair.sk))
            })
    }

    pub fn sign_block(
        &self,
        validator_pubkey: &PublicKey,
        mut block: BeaconBlock<E>,
    ) -> Option<BeaconBlock<E>> {
        let validators = self.validators.read();

        // Retrieving the corresponding ValidatorDir
        let validator = match validators.get(validator_pubkey) {
            Some(validator) => validator,
            None => return None, // SCOTT maybe log that validator was not found?
        };

        if validator.block_slashing_protection.is_none() {
            error!(
                self.log,
                "Validator does not have block slashing protection";
                "action" => "refused to produce block",
                "pubkey" => format!("{:?}", &validator.voting_keypair.pk),
            )
        }

        // Checking for slashing conditions
        let is_slashing_free = validator
            .block_slashing_protection
            .as_ref()?
            .try_lock()? // SCOTT TODO: deal with the try_lock failing? retry?
            .update_if_valid(&block.block_header())
            .is_ok();

        if is_slashing_free {
            // We can safely sign this block
            let voting_keypair = &validator.voting_keypair;
            block.sign(&voting_keypair.sk, &self.fork()?, &self.spec);
            Some(block)
        } else {
            None
        }
    }

    pub fn sign_attestation(
        &self,
        validator_pubkey: &PublicKey,
        validator_committee_position: usize,
        attestation: &mut Attestation<E>,
    ) -> Option<()> {
        let validators = self.validators.read();

        // Retrieving the corresponding ValidatorDir
        let validator = match validators.get(validator_pubkey) {
            Some(validator) => validator,
            None => return None,
        };

        if validator.attestation_slashing_protection.is_none() {
            error!(
                self.log,
                "Validator does not have attestation slashing protection";
                "action" => "refused to produce attestation",
                "pubkey" => format!("{:?}", &validator.voting_keypair.pk),
            )
        }

        // Checking for slashing conditions
        let is_slashing_free = validator
            .attestation_slashing_protection
            .as_ref()?
            .try_lock()? // SCOTT TODO: deal with the try_lock failing? retry?
            .update_if_valid(&attestation.data)
            .is_ok();

        if is_slashing_free {
            // We can safely sign this attestation
            let voting_keypair = &validator.voting_keypair;

            attestation
                .sign(
                    &voting_keypair.sk,
                    validator_committee_position,
                    &self.fork()?,
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
        } else {
            None
        }
    }
}
