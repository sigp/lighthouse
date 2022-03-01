use crate::{metrics, DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use std::io::{Read, Write};
use types::{beacon_state::BeaconStateDiff, EthSpec};
use zstd::{Decoder, Encoder};

const EST_COMPRESSION_FACTOR: usize = 2;

fn estimate_compressed_size(len: usize, compression_level: i32) -> usize {
    if compression_level == 0 {
        len
    } else {
        len / EST_COMPRESSION_FACTOR
    }
}

impl<E: EthSpec> StoreItem for BeaconStateDiff<E> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateDiff
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        let encode_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_ENCODE_TIME);
        let value = self.as_ssz_bytes();
        drop(encode_timer);

        let compression_timer = metrics::start_timer(&metrics::BEACON_STATE_DIFF_COMPRESSION_TIME);

        let level = 1;
        let mut compressed_value = Vec::with_capacity(estimate_compressed_size(value.len(), level));
        let mut encoder = Encoder::new(&mut compressed_value, level).map_err(Error::Compression)?;
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

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut ssz_bytes = Vec::with_capacity(EST_COMPRESSION_FACTOR * bytes.len());
        let mut decoder = Decoder::new(bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut ssz_bytes)
            .map_err(Error::Compression)?;
        Ok(Self::from_ssz_bytes(&ssz_bytes)?)
    }
}
