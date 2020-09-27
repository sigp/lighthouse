use crate::naive_aggregation_pool::SszNaiveAggregationPool;
use crate::observed_attestations::SszObservedAttestations;
use crate::observed_attesters::{SszAutoPruningContainer, SszEpochBitfield, SszEpochHashSet};
use crate::observed_block_producers::SszObservedBlockProducers;
use crate::observed_operations::SszObservedOperations;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error, StoreItem};
use types::EthSpec;

#[derive(Encode, Decode)]
pub struct PersistedSeenCaches<E: EthSpec> {
    pub naive_aggregation_pool: SszNaiveAggregationPool<E>,
    pub observed_attestations: SszObservedAttestations,
    pub observed_attesters: SszAutoPruningContainer<SszEpochBitfield>,
    pub observed_aggregators: SszAutoPruningContainer<SszEpochHashSet>,
    pub observed_block_producers: SszObservedBlockProducers,
    pub observed_voluntary_exits: SszObservedOperations,
    pub observed_proposer_slashings: SszObservedOperations,
    pub observed_attester_slashings: SszObservedOperations,
}

impl<E: EthSpec> StoreItem for PersistedSeenCaches<E> {
    fn db_column() -> DBColumn {
        DBColumn::SeenCaches
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
