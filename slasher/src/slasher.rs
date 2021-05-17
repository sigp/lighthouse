use crate::batch_stats::{AttestationStats, BatchStats, BlockStats};
use crate::metrics::{
    self, SLASHER_NUM_ATTESTATIONS_DEFERRED, SLASHER_NUM_ATTESTATIONS_DROPPED,
    SLASHER_NUM_ATTESTATIONS_VALID, SLASHER_NUM_BLOCKS_PROCESSED,
};
use crate::{
    array, AttestationBatch, AttestationQueue, AttesterRecord, BlockQueue, Config, Error,
    ProposerSlashingStatus, SlasherDB,
};
use lmdb::{RwTransaction, Transaction};
use parking_lot::Mutex;
use slog::{debug, error, info, Logger};
use std::collections::HashSet;
use std::sync::Arc;
use types::{
    AttesterSlashing, Epoch, EthSpec, IndexedAttestation, ProposerSlashing, SignedBeaconBlockHeader,
};

#[derive(Debug)]
pub struct Slasher<E: EthSpec> {
    db: SlasherDB<E>,
    attestation_queue: AttestationQueue<E>,
    block_queue: BlockQueue,
    attester_slashings: Mutex<HashSet<AttesterSlashing<E>>>,
    proposer_slashings: Mutex<HashSet<ProposerSlashing>>,
    config: Arc<Config>,
    log: Logger,
}

impl<E: EthSpec> Slasher<E> {
    pub fn open(config: Config, log: Logger) -> Result<Self, Error> {
        config.validate()?;
        let config = Arc::new(config);
        let db = SlasherDB::open(config.clone())?;
        let attester_slashings = Mutex::new(HashSet::new());
        let proposer_slashings = Mutex::new(HashSet::new());
        let attestation_queue = AttestationQueue::default();
        let block_queue = BlockQueue::default();
        Ok(Self {
            db,
            attestation_queue,
            block_queue,
            attester_slashings,
            proposer_slashings,
            config,
            log,
        })
    }

    /// Harvest all attester slashings found, removing them from the slasher.
    pub fn get_attester_slashings(&self) -> HashSet<AttesterSlashing<E>> {
        std::mem::take(&mut self.attester_slashings.lock())
    }

    /// Harvest all proposer slashings found, removing them from the slasher.
    pub fn get_proposer_slashings(&self) -> HashSet<ProposerSlashing> {
        std::mem::take(&mut self.proposer_slashings.lock())
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn log(&self) -> &Logger {
        &self.log
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
    pub fn process_queued(&self, current_epoch: Epoch) -> Result<BatchStats, Error> {
        let mut txn = self.db.begin_rw_txn()?;
        let block_stats = self.process_blocks(&mut txn)?;
        let attestation_stats = self.process_attestations(current_epoch, &mut txn)?;
        txn.commit()?;
        Ok(BatchStats {
            block_stats,
            attestation_stats,
        })
    }

    /// Apply queued blocks to the on-disk database.
    ///
    /// Return the number of blocks
    pub fn process_blocks(&self, txn: &mut RwTransaction<'_>) -> Result<BlockStats, Error> {
        let blocks = self.block_queue.dequeue();
        let num_processed = blocks.len();
        let mut slashings = vec![];

        metrics::set_gauge(&SLASHER_NUM_BLOCKS_PROCESSED, blocks.len() as i64);

        for block in blocks {
            if let ProposerSlashingStatus::DoubleVote(slashing) =
                self.db.check_or_insert_block_proposal(txn, block)?
            {
                slashings.push(*slashing);
            }
        }

        let num_slashings = slashings.len();
        if !slashings.is_empty() {
            info!(
                self.log,
                "Found {} new proposer slashings!",
                slashings.len(),
            );
            self.proposer_slashings.lock().extend(slashings);
        }

        Ok(BlockStats {
            num_processed,
            num_slashings,
        })
    }

    /// Apply queued attestations to the on-disk database.
    pub fn process_attestations(
        &self,
        current_epoch: Epoch,
        txn: &mut RwTransaction<'_>,
    ) -> Result<AttestationStats, Error> {
        let snapshot = self.attestation_queue.dequeue();
        let num_processed = snapshot.len();

        // Filter attestations for relevance.
        let (snapshot, deferred, num_dropped) = self.validate(snapshot, current_epoch);
        let num_deferred = deferred.len();
        self.attestation_queue.requeue(deferred);

        // Insert attestations into database.
        debug!(
            self.log,
            "Storing attestations in slasher DB";
            "num_valid" => snapshot.len(),
            "num_deferred" => num_deferred,
            "num_dropped" => num_dropped,
        );
        metrics::set_gauge(&SLASHER_NUM_ATTESTATIONS_VALID, snapshot.len() as i64);
        metrics::set_gauge(&SLASHER_NUM_ATTESTATIONS_DEFERRED, num_deferred as i64);
        metrics::set_gauge(&SLASHER_NUM_ATTESTATIONS_DROPPED, num_dropped as i64);

        for attestation in snapshot.attestations.iter() {
            self.db.store_indexed_attestation(
                txn,
                attestation.1.indexed_attestation_hash,
                &attestation.0,
            )?;
        }

        // Group attestations into batches and process them.
        let grouped_attestations = snapshot.group_by_validator_index(&self.config);
        for (subqueue_id, subqueue) in grouped_attestations.subqueues.into_iter().enumerate() {
            self.process_batch(txn, subqueue_id, subqueue.attestations, current_epoch)?;
        }
        Ok(AttestationStats { num_processed })
    }

    /// Process a batch of attestations for a range of validator indices.
    fn process_batch(
        &self,
        txn: &mut RwTransaction<'_>,
        subqueue_id: usize,
        batch: Vec<Arc<(IndexedAttestation<E>, AttesterRecord)>>,
        current_epoch: Epoch,
    ) -> Result<(), Error> {
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
                    return Err(e);
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
                return Err(e);
            }
        }

        Ok(())
    }

    /// Check for double votes from all validators on `attestation` who match the `subqueue_id`.
    fn check_double_votes(
        &self,
        txn: &mut RwTransaction<'_>,
        subqueue_id: usize,
        attestation: &IndexedAttestation<E>,
        attester_record: AttesterRecord,
    ) -> Result<HashSet<AttesterSlashing<E>>, Error> {
        let mut slashings = HashSet::new();

        for validator_index in self
            .config
            .attesting_validators_in_chunk(attestation, subqueue_id)
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
                slashings.insert(slashing);
            }
        }

        Ok(slashings)
    }

    /// Validate the attestations in `batch` for ingestion during `current_epoch`.
    ///
    /// Drop any attestations that are too old to ever be relevant, and return any attestations
    /// that might be valid in the future.
    ///
    /// Returns `(valid, deferred, num_dropped)`.
    fn validate(
        &self,
        batch: AttestationBatch<E>,
        current_epoch: Epoch,
    ) -> (AttestationBatch<E>, AttestationBatch<E>, usize) {
        let mut keep = Vec::with_capacity(batch.len());
        let mut defer = vec![];
        let mut drop_count = 0;

        for tuple in batch.attestations.into_iter() {
            let attestation = &tuple.0;
            let target_epoch = attestation.data.target.epoch;
            let source_epoch = attestation.data.source.epoch;

            if source_epoch > target_epoch
                || source_epoch + self.config.history_length as u64 <= current_epoch
            {
                drop_count += 1;
                continue;
            }

            // Check that the attestation's target epoch is acceptable, and defer it
            // if it's not.
            if target_epoch > current_epoch {
                defer.push(tuple);
            } else {
                // Otherwise the attestation is OK to process.
                keep.push(tuple);
            }
        }

        (
            AttestationBatch { attestations: keep },
            AttestationBatch {
                attestations: defer,
            },
            drop_count,
        )
    }

    /// Prune unnecessary attestations and blocks from the on-disk database.
    pub fn prune_database(&self, current_epoch: Epoch) -> Result<(), Error> {
        self.db.prune(current_epoch)
    }
}
