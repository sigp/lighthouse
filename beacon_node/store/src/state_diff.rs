use crate::{metrics, DBColumn, Error, StoreItem};
use flate2::bufread::{ZlibDecoder, ZlibEncoder};
use ssz::{Decode, Encode};
use std::io::Read;
use types::{beacon_state::BeaconStateDiff, EthSpec};

impl<E: EthSpec> StoreItem for BeaconStateDiff<E> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateDiff
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        let encode_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_ENCODE_TIME);
        let value = self.as_ssz_bytes();
        drop(encode_timer);

        // FIXME(sproul): try vec with capacity
        let compression_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_COMPRESSION_TIME);
        let mut encoder = ZlibEncoder::new(&value[..], flate2::Compression::fast());
        let mut compressed_value = vec![];
        encoder
            .read_to_end(&mut compressed_value)
            .map_err(Error::FlateCompression)?;
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

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut ssz_bytes = vec![];
        let mut decoder = ZlibDecoder::new(bytes);
        decoder
            .read_to_end(&mut ssz_bytes)
            .map_err(Error::FlateCompression)?;
        Ok(Self::from_ssz_bytes(&ssz_bytes)?)
    }
}
