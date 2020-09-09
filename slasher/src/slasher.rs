use crate::{array, AttestationQueue, Config, Error, SlasherDB};
use lmdb::{RwTransaction, Transaction};
use parking_lot::Mutex;
use slog::{debug, error, info, Logger};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{AttesterSlashing, Epoch, EthSpec, IndexedAttestation};

#[derive(Debug)]
pub struct Slasher<E: EthSpec> {
    db: SlasherDB<E>,
    pub(crate) attestation_queue: AttestationQueue<E>,
    // TODO: consider using a set
    attester_slashings: Mutex<Vec<AttesterSlashing<E>>>,
    // TODO: consider removing Arc
    config: Arc<Config>,
    pub(crate) log: Logger,
}

impl<E: EthSpec> Slasher<E> {
    pub fn open(config: Config, log: Logger) -> Result<Self, Error> {
        config.validate()?;
        let config = Arc::new(config);
        let db = SlasherDB::open(config.clone())?;
        let attester_slashings = Mutex::new(vec![]);
        let attestation_queue = AttestationQueue::new(config.validator_chunk_size);
        Ok(Self {
            db,
            attester_slashings,
            attestation_queue,
            config,
            log,
        })
    }

    pub fn get_attester_slashings(&self) -> Vec<AttesterSlashing<E>> {
        std::mem::replace(&mut self.attester_slashings.lock(), vec![])
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Accept an attestation from the network and queue it for processing.
    pub fn accept_attestation(&self, attestation: IndexedAttestation<E>) {
        self.attestation_queue.queue(attestation);
    }

    /// Apply queued attestations to the on-disk database.
    pub fn process_attestations(&self, current_epoch: Epoch) -> Result<(), Error> {
        let snapshot = self.attestation_queue.get_snapshot();
        let mut txn = self.db.begin_rw_txn()?;

        // Insert attestations into database.
        for attestation in snapshot.attestations_to_store {
            self.db.store_indexed_attestation(&mut txn, &attestation)?;
        }

        // Dequeue attestations in batches and process them.
        for (subqueue_id, subqueue) in snapshot.subqueues.into_iter().enumerate() {
            self.process_batch(&mut txn, subqueue_id, subqueue.attestations, current_epoch);
        }
        txn.commit()?;
        Ok(())
    }

    /// Process a batch of attestations for a range of validator indices.
    fn process_batch(
        &self,
        txn: &mut RwTransaction<'_>,
        subqueue_id: usize,
        batch: Vec<Arc<IndexedAttestation<E>>>,
        current_epoch: Epoch,
    ) {
        // First, check for double votes.
        for attestation in &batch {
            match self.check_double_votes(txn, subqueue_id, &attestation) {
                Ok(slashings) => {
                    if !slashings.is_empty() {
                        info!(
                            self.log,
                            "Found {} new double-vote slashings!",
                            slashings.len()
                        );
                    }
                    self.attester_slashings.lock().extend(slashings);
                }
                Err(e) => {
                    error!(
                        self.log,
                        "Error checking for double votes";
                        "error" => format!("{:?}", e)
                    );
                }
            }
        }

        // Then check for surrounds using the min-max arrays.
        match array::update(
            &self.db,
            txn,
            subqueue_id,
            batch,
            current_epoch,
            &self.config,
        ) {
            Ok(slashings) => {
                if !slashings.is_empty() {
                    info!(
                        self.log,
                        "Found {} new surround slashings!",
                        slashings.len()
                    );
                }
                self.attester_slashings.lock().extend(slashings);
            }
            Err(e) => {
                error!(
                    self.log,
                    "Error processing array update";
                    "error" => format!("{:?}", e),
                );
            }
        }
    }

    /// Check for double votes from all validators on `attestation` who match the `subqueue_id`.
    fn check_double_votes(
        &self,
        txn: &mut RwTransaction<'_>,
        subqueue_id: usize,
        attestation: &IndexedAttestation<E>,
    ) -> Result<Vec<AttesterSlashing<E>>, Error> {
        let attestation_data_hash = attestation.data.tree_hash_root();
        let indexed_attestation_hash = attestation.tree_hash_root();

        let mut slashings = vec![];

        for validator_index in self
            .config
            .attesting_validators_for_chunk(attestation, subqueue_id)
        {
            let slashing_status = self.db.check_and_update_attester_record(
                txn,
                validator_index,
                &attestation,
                attestation_data_hash,
                indexed_attestation_hash,
            )?;

            if let Some(slashing) = slashing_status.into_slashing(attestation) {
                debug!(
                    self.log,
                    "Found double-vote slashing";
                    "validator_index" => validator_index,
                    "epoch" => slashing.attestation_1.data.target.epoch,
                );

                // Avoid creating duplicate slashings for the same attestation.
                // PERF: this is O(n) instead of O(1), but n should be small.
                if !slashings.contains(&slashing) {
                    slashings.push(slashing);
                }
            }
        }

        Ok(slashings)
    }
}
