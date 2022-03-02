use crate::{
    get_key_for_col, hot_cold_store::HotColdDBError, metrics, DBColumn, Error, HotColdDB,
    ItemStore, KeyValueStore, KeyValueStoreOp,
};
use ssz::{Decode, Encode};
use std::io::{Read, Write};
use types::{beacon_state::BeaconStateDiff, EthSpec, Hash256};
use zstd::{Decoder, Encoder};

impl<E, Hot, Cold> HotColdDB<E, Hot, Cold>
where
    E: EthSpec,
    Hot: KeyValueStore<E> + ItemStore<E>,
    Cold: KeyValueStore<E> + ItemStore<E>,
{
    pub fn load_state_diff(&self, state_root: Hash256) -> Result<BeaconStateDiff<E>, Error> {
        let bytes = self
            .hot_db
            .get_bytes(DBColumn::BeaconStateDiff.into(), state_root.as_bytes())?
            .ok_or(HotColdDBError::MissingStateDiff(state_root))?;

        let mut ssz_bytes = Vec::with_capacity(self.config.estimate_decompressed_size(bytes.len()));
        let mut decoder = Decoder::new(&*bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut ssz_bytes)
            .map_err(Error::Compression)?;
        Ok(BeaconStateDiff::from_ssz_bytes(&ssz_bytes)?)
    }

    pub fn state_diff_as_bytes(&self, diff: &BeaconStateDiff<E>) -> Result<Vec<u8>, Error> {
        let encode_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_ENCODE_TIME);
        let value = diff.as_ssz_bytes();
        drop(encode_timer);

        let compression_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_COMPRESSION_TIME);

        let mut compressed_value =
            Vec::with_capacity(self.config.estimate_compressed_size(value.len()));
        let mut encoder = Encoder::new(&mut compressed_value, self.config.compression_level)
            .map_err(Error::Compression)?;
        encoder.write_all(&value).map_err(Error::Compression)?;
        encoder.finish().map_err(Error::Compression)?;
        drop(compression_timer);

        let compression_ratio = value.len() as f64 / compressed_value.len() as f64;
        metrics::set_float_gauge(
            &metrics::BEACON_STATE_DIFF_COMPRESSION_RATIO,
            compression_ratio,
        );

        metrics::inc_counter_by(
            &metrics::BEACON_STATE_DIFF_WRITE_BYTES,
            compressed_value.len() as u64,
        );
        metrics::inc_counter(&metrics::BEACON_STATE_DIFF_WRITE_COUNT);

        Ok(compressed_value)
    }

    pub fn state_diff_as_kv_store_op(
        &self,
        state_root: &Hash256,
        diff: &BeaconStateDiff<E>,
    ) -> Result<KeyValueStoreOp, Error> {
        let key = get_key_for_col(DBColumn::BeaconStateDiff.into(), state_root.as_bytes());
        let value = self.state_diff_as_bytes(diff)?;
        Ok(KeyValueStoreOp::PutKeyValue(key, value))
    }
}
