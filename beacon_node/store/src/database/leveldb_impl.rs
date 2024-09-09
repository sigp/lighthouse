use crate::hot_cold_store::{BytesKey, HotColdDBError};
use crate::Key;
use crate::{
    get_key_for_col, metrics, ColumnIter, ColumnKeyIter, DBColumn, Error, KeyValueStoreOp,
};
use leveldb::{
    compaction::Compaction,
    database::{
        batch::{Batch, Writebatch},
        kv::KV,
        Database,
    },
    iterator::{Iterable, LevelDBIterator},
    options::{Options, ReadOptions},
};
use parking_lot::{Mutex, MutexGuard};
use std::marker::PhantomData;
use std::path::Path;
use types::{EthSpec, FixedBytesExtended, Hash256};

use super::interface::WriteOptions;

pub struct LevelDB<E: EthSpec> {
    db: Database<BytesKey>,
    /// A mutex to synchronise sensitive read-write transactions.
    transaction_mutex: Mutex<()>,
    _phantom: PhantomData<E>,
}

impl From<WriteOptions> for leveldb::options::WriteOptions {
    fn from(options: WriteOptions) -> Self {
        // Assuming LevelDBWriteOptions has a new method that accepts a bool parameter for sync.
        let mut opts = leveldb::options::WriteOptions::new();
        opts.sync = options.sync;
        opts
    }
}

impl<E: EthSpec> LevelDB<E> {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();

        options.create_if_missing = true;

        let db = Database::open(path, options)?;
        let transaction_mutex = Mutex::new(());

        Ok(Self {
            db,
            transaction_mutex,
            _phantom: PhantomData,
        })
    }

    pub fn read_options(&self) -> ReadOptions<BytesKey> {
        ReadOptions::new()
    }

    pub fn write_options(&self) -> WriteOptions {
        WriteOptions::new()
    }

    pub fn write_options_sync(&self) -> WriteOptions {
        let mut opts = WriteOptions::new();
        opts.sync = true;
        opts
    }

    pub fn put_bytes_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions,
    ) -> Result<(), Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter_vec(&metrics::DISK_DB_WRITE_COUNT, &[col]);
        metrics::inc_counter_vec_by(&metrics::DISK_DB_WRITE_BYTES, &[col], val.len() as u64);
        let timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);

        self.db
            .put(opts.into(), BytesKey::from_vec(column_key), val)
            .map_err(Into::into)
            .map(|()| {
                metrics::stop_timer(timer);
            })
    }

    /// Store some `value` in `column`, indexed with `key`.
    pub fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options())
    }

    pub fn put_bytes_sync(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options_sync())
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.put_bytes_sync("sync", b"sync", b"sync")
    }

    // Retrieve some bytes in `column` with `key`.
    pub fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter_vec(&metrics::DISK_DB_READ_COUNT, &[col]);
        let timer = metrics::start_timer(&metrics::DISK_DB_READ_TIMES);

        self.db
            .get(self.read_options(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
            .map(|opt| {
                opt.inspect(|bytes| {
                    metrics::inc_counter_vec_by(
                        &metrics::DISK_DB_READ_BYTES,
                        &[col],
                        bytes.len() as u64,
                    );
                    metrics::stop_timer(timer);
                })
            })
    }

    /// Return `true` if `key` exists in `column`.
    pub fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter_vec(&metrics::DISK_DB_EXISTS_COUNT, &[col]);

        self.db
            .get(self.read_options(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
            .map(|val| val.is_some())
    }

    /// Removes `key` from `column`.
    pub fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter_vec(&metrics::DISK_DB_DELETE_COUNT, &[col]);

        self.db
            .delete(self.write_options().into(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        let mut leveldb_batch = Writebatch::new();
        for op in ops_batch {
            match op {
                KeyValueStoreOp::PutKeyValue(col, key, value) => {
                    let _timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);
                    metrics::inc_counter_vec_by(
                        &metrics::DISK_DB_WRITE_BYTES,
                        &[&col],
                        value.len() as u64,
                    );
                    metrics::inc_counter_vec(&metrics::DISK_DB_WRITE_COUNT, &[&col]);
                    let column_key = get_key_for_col(&col, &key);
                    leveldb_batch.put(BytesKey::from_vec(column_key), &value);
                }

                KeyValueStoreOp::DeleteKey(col, key) => {
                    let _timer = metrics::start_timer(&metrics::DISK_DB_DELETE_TIMES);
                    metrics::inc_counter_vec(&metrics::DISK_DB_DELETE_COUNT, &[&col]);
                    let column_key = get_key_for_col(&col, &key);
                    leveldb_batch.delete(BytesKey::from_vec(column_key));
                }
            }
        }
        self.db.write(self.write_options().into(), &leveldb_batch)?;
        Ok(())
    }

    pub fn begin_rw_transaction(&self) -> MutexGuard<()> {
        self.transaction_mutex.lock()
    }

    /// Compact all values in the states and states flag columns.
    pub fn compact(&self) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::DISK_DB_COMPACT_TIMES);
        let endpoints = |column: DBColumn| {
            (
                BytesKey::from_vec(get_key_for_col(column.as_str(), Hash256::zero().as_slice())),
                BytesKey::from_vec(get_key_for_col(
                    column.as_str(),
                    Hash256::repeat_byte(0xff).as_slice(),
                )),
            )
        };

        for (start_key, end_key) in [
            endpoints(DBColumn::BeaconStateTemporary),
            endpoints(DBColumn::BeaconState),
            endpoints(DBColumn::BeaconStateSummary),
        ] {
            self.db.compact(&start_key, &end_key);
        }

        Ok(())
    }

    pub fn compact_column(&self, column: DBColumn) -> Result<(), Error> {
        // Use key-size-agnostic keys [] and 0xff..ff with a minimum of 32 bytes to account for
        // columns that may change size between sub-databases or schema versions.
        let start_key = BytesKey::from_vec(get_key_for_col(column.as_str(), &[]));
        let end_key = BytesKey::from_vec(get_key_for_col(
            column.as_str(),
            &vec![0xff; std::cmp::max(column.key_size(), 32)],
        ));
        self.db.compact(&start_key, &end_key);
        Ok(())
    }

    pub fn iter_column_from<K: Key>(
        &self,
        column: DBColumn,
        from: &[u8],
        predicate: impl Fn(&[u8], &[u8]) -> bool + 'static,
    ) -> ColumnIter<K> {
        let start_key = BytesKey::from_vec(get_key_for_col(column.into(), from));

        let iter = self.db.iter(self.read_options());
        iter.seek(&start_key);

        Ok(Box::new(
            iter.take_while(move |(key, _)| {
                let Some(trimmed_key) = key.remove_column_variable(column) else {
                    return false;
                };
                let Some(trimmed_start_key) = start_key.remove_column_variable(column) else {
                    return false;
                };
                key.matches_column(column) && predicate(trimmed_key, trimmed_start_key)
            })
            .map(move |(bytes_key, value)| {
                metrics::inc_counter_vec(&metrics::DISK_DB_READ_COUNT, &[column.into()]);
                metrics::inc_counter_vec_by(
                    &metrics::DISK_DB_READ_BYTES,
                    &[column.into()],
                    value.len() as u64,
                );
                let key = bytes_key.remove_column_variable(column).ok_or_else(|| {
                    HotColdDBError::IterationError {
                        unexpected_key: bytes_key.clone(),
                    }
                })?;
                Ok((K::from_bytes(key)?, value))
            }),
        ))
    }

    pub fn iter_column_keys_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnKeyIter<K> {
        let start_key = BytesKey::from_vec(get_key_for_col(column.into(), from));

        let iter = self.db.keys_iter(self.read_options());
        iter.seek(&start_key);

        Ok(Box::new(
            iter.take_while(move |key| key.matches_column(column))
                .map(move |bytes_key| {
                    metrics::inc_counter_vec(&metrics::DISK_DB_KEY_READ_COUNT, &[column.into()]);
                    metrics::inc_counter_vec_by(
                        &metrics::DISK_DB_KEY_READ_BYTES,
                        &[column.into()],
                        bytes_key.key.len() as u64,
                    );
                    let key = &bytes_key.key[column.as_bytes().len()..];
                    K::from_bytes(key)
                }),
        ))
    }

    /// Iterate through all keys and values in a particular column.
    pub fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<K> {
        self.iter_column_keys_from(column, &vec![0; column.key_size()])
    }

    pub fn iter_column<K: Key>(&self, column: DBColumn) -> ColumnIter<K> {
        self.iter_column_from(column, &vec![0; column.key_size()], move |key, _| {
            metrics::inc_counter_vec(&metrics::DISK_DB_READ_COUNT, &[column.into()]);
            BytesKey::from_vec(key.to_vec()).matches_column(column)
        })
    }
}
