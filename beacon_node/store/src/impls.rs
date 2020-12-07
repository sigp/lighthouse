use crate::*;
use ssz::{Decode, Encode};

pub mod beacon_state;
pub mod partial_beacon_state;

impl<T: EthSpec> StoreItem for SignedBeaconBlock<T> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconBlock
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        let timer = metrics::start_timer(&metrics::BEACON_BLOCK_WRITE_TIMES);
        let bytes = self.as_ssz_bytes();

        metrics::stop_timer(timer);
        metrics::inc_counter(&metrics::BEACON_BLOCK_WRITE_COUNT);
        metrics::inc_counter_by(&metrics::BEACON_BLOCK_WRITE_BYTES, bytes.len() as u64);

        bytes
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let timer = metrics::start_timer(&metrics::BEACON_BLOCK_READ_TIMES);

        let len = bytes.len();
        let result = Self::from_ssz_bytes(bytes).map_err(Into::into);

        metrics::stop_timer(timer);
        metrics::inc_counter(&metrics::BEACON_BLOCK_READ_COUNT);
        metrics::inc_counter_by(&metrics::BEACON_BLOCK_READ_BYTES, len as u64);

        result
    }
}
