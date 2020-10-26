use crate::{
    array, AttestationQueue, AttesterRecord, BlockQueue, Config, Error, ProposerSlashingStatus,
    SlasherDB,
};
use lmdb::{RwTransaction, Transaction};
use parking_lot::Mutex;
use slog::{debug, error, info, Logger};
use std::sync::Arc;
use types::{
    AttesterSlashing, Epoch, EthSpec, IndexedAttestation, ProposerSlashing, SignedBeaconBlockHeader,
};

#[derive(Debug)]
pub struct Slasher<E: EthSpec> {
    db: SlasherDB<E>,
    pub(crate) attestation_queue: AttestationQueue<E>,
    pub(crate) block_queue: BlockQueue,
    // TODO: consider using a set
    attester_slashings: Mutex<Vec<AttesterSlashing<E>>>,
    proposer_slashings: Mutex<Vec<ProposerSlashing>>,
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
        let proposer_slashings = Mutex::new(vec![]);
        let attestation_queue = AttestationQueue::new(config.validator_chunk_size);
        let block_queue = BlockQueue::new();
        Ok(Self {
            db,
            attester_slashings,
            proposer_slashings,
            attestation_queue,
            block_queue,
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

    /// Accept a block from the network and queue it for processing.
    pub fn accept_block_header(&self, block_header: SignedBeaconBlockHeader) {
        self.block_queue.queue(block_header);
    }

    /// Apply queued blocks and attestations to the on-disk database, and detect slashings!
    pub fn process_queued(&self, current_epoch: Epoch) -> Result<(), Error> {
        let mut txn = self.db.begin_rw_txn()?;
        self.process_blocks(&mut txn)?;
        self.process_attestations(current_epoch, &mut txn)?;
        txn.commit()?;
        Ok(())
    }

    /// Apply queued blocks to the on-disk database.
    pub fn process_blocks(&self, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        let blocks = self.block_queue.dequeue();
        let mut slashings = vec![];

        for block in blocks {
            if let ProposerSlashingStatus::DoubleVote(slashing) =
                self.db.check_or_insert_block_proposal(txn, block)?
            {
                slashings.push(*slashing);
            }
        }

        if !slashings.is_empty() {
            info!(
                self.log,
                "Found {} new proposer slashings!",
                slashings.len(),
            );
            self.proposer_slashings.lock().extend(slashings);
        }

        Ok(())
    }

    /// Apply queued attestations to the on-disk database.
    pub fn process_attestations(
        &self,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<(), Error> {
        let snapshot = self.attestation_queue.get_snapshot();

        // Insert attestations into database.
        debug!(
            self.log,
            "Storing {} attestations in slasher DB",
            snapshot.attestations_to_store.len()
        );
        for attestation in snapshot.attestations_to_store {
            self.db.store_indexed_attestation(
                txn,
                attestation.1.indexed_attestation_hash,
                &attestation.0,
            )?;
        }

        // Dequeue attestations in batches and process them.
        for (subqueue_id, subqueue) in snapshot.subqueues.into_iter().enumerate() {
            self.process_batch(txn, subqueue_id, subqueue.attestations, current_epoch);
        }
        Ok(())
    }

    /// Process a batch of attestations for a range of validator indices.
    fn process_batch(
        &self,
        txn: &mut RwTransaction<'_>,
        subqueue_id: usize,
        batch: Vec<Arc<(IndexedAttestation<E>, AttesterRecord)>>,
        current_epoch: Epoch,
    ) {
        // First, check for double votes.
        for attestation in &batch {
            match self.check_double_votes(txn, subqueue_id, &attestation.0, attestation.1) {
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
        attester_record: AttesterRecord,
    ) -> Result<Vec<AttesterSlashing<E>>, Error> {
        let mut slashings = vec![];

        for validator_index in self
            .config
            .attesting_validators_for_chunk(attestation, subqueue_id)
        {
            let slashing_status = self.db.check_and_update_attester_record(
                txn,
                validator_index,
                &attestation,
                attester_record,
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
