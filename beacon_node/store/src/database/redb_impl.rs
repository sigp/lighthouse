use crate::{metrics, ColumnIter, ColumnKeyIter, Key};
use crate::{DBColumn, Error, KeyValueStoreOp};
use parking_lot::{Mutex, MutexGuard, RwLock};
use redb::TableDefinition;
use std::collections::HashSet;
use std::{borrow::BorrowMut, marker::PhantomData, path::Path};
use strum::IntoEnumIterator;
use types::EthSpec;

use super::interface::WriteOptions;

pub const DB_FILE_NAME: &str = "database.redb";

pub struct Redb<E: EthSpec> {
    db: RwLock<redb::Database>,
    transaction_mutex: Mutex<()>,
    _phantom: PhantomData<E>,
}

impl From<WriteOptions> for redb::Durability {
    fn from(options: WriteOptions) -> Self {
        if options.sync {
            redb::Durability::Immediate
        } else {
            redb::Durability::Eventual
        }
    }
}

impl<E: EthSpec> Redb<E> {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let db_file = path.join(DB_FILE_NAME);
        let db = redb::Database::create(db_file)?;
        let transaction_mutex = Mutex::new(());

        for column in DBColumn::iter() {
            Redb::<E>::create_table(&db, column.into())?;
        }

        Ok(Self {
            db: db.into(),
            transaction_mutex,
            _phantom: PhantomData,
        })
    }

    fn create_table(db: &redb::Database, table_name: &str) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(table_name);
        let tx = db.begin_write()?;
        tx.open_table(table_definition)?;
        tx.commit().map_err(Into::into)
    }

    pub fn write_options(&self) -> WriteOptions {
        WriteOptions::new()
    }

    pub fn write_options_sync(&self) -> WriteOptions {
        let mut opts = WriteOptions::new();
        opts.sync = true;
        opts
    }

    pub fn begin_rw_transaction(&self) -> MutexGuard<()> {
        self.transaction_mutex.lock()
    }

    pub fn put_bytes_with_options(
        &self,
        col: DBColumn,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions,
    ) -> Result<(), Error> {
        metrics::inc_counter_vec(&metrics::DISK_DB_WRITE_COUNT, &[col.into()]);
        metrics::inc_counter_vec_by(
            &metrics::DISK_DB_WRITE_BYTES,
            &[col.into()],
            val.len() as u64,
        );
        let timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);

        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(col.into());
        let open_db = self.db.read();
        let mut tx = open_db.begin_write()?;
        tx.set_durability(opts.into());
        let mut table = tx.open_table(table_definition)?;

        table.insert(key, val).map(|_| {
            metrics::stop_timer(timer);
        })?;
        drop(table);
        tx.commit().map_err(Into::into)
    }

    /// Store some `value` in `column`, indexed with `key`.
    pub fn put_bytes(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options())
    }

    pub fn put_bytes_sync(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options_sync())
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.put_bytes_sync(DBColumn::Dummy, b"sync", b"sync")
    }

    // Retrieve some bytes in `column` with `key`.
    pub fn get_bytes(&self, col: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        metrics::inc_counter_vec(&metrics::DISK_DB_READ_COUNT, &[col.into()]);
        let timer = metrics::start_timer(&metrics::DISK_DB_READ_TIMES);

        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(col.into());
        let open_db = self.db.read();
        let tx = open_db.begin_read()?;
        let table = tx.open_table(table_definition)?;

        let result = table.get(key)?;

        match result {
            Some(access_guard) => {
                let value = access_guard.value().to_vec();
                metrics::inc_counter_vec_by(
                    &metrics::DISK_DB_READ_BYTES,
                    &[col.into()],
                    value.len() as u64,
                );
                metrics::stop_timer(timer);
                Ok(Some(value))
            }
            None => {
                metrics::stop_timer(timer);
                Ok(None)
            }
        }
    }

    /// Return `true` if `key` exists in `column`.
    pub fn key_exists(&self, col: DBColumn, key: &[u8]) -> Result<bool, Error> {
        metrics::inc_counter_vec(&metrics::DISK_DB_EXISTS_COUNT, &[col.into()]);

        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(col.into());
        let open_db = self.db.read();
        let tx = open_db.begin_read()?;
        let table = tx.open_table(table_definition)?;

        table
            .get(key)
            .map_err(Into::into)
            .map(|access_guard| access_guard.is_some())
    }

    /// Removes `key` from `column`.
    pub fn key_delete(&self, col: DBColumn, key: &[u8]) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(col.into());
        let open_db = self.db.read();
        let tx = open_db.begin_write()?;
        let mut table = tx.open_table(table_definition)?;
        metrics::inc_counter_vec(&metrics::DISK_DB_DELETE_COUNT, &[col.into()]);

        table.remove(key).map(|_| ())?;
        drop(table);
        tx.commit().map_err(Into::into)
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        let open_db = self.db.read();
        let mut tx = open_db.begin_write()?;
        tx.set_durability(self.write_options().into());
        for op in ops_batch {
            match op {
                KeyValueStoreOp::PutKeyValue(column, key, value) => {
                    let _timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);
                    metrics::inc_counter_vec_by(
                        &metrics::DISK_DB_WRITE_BYTES,
                        &[column.into()],
                        value.len() as u64,
                    );
                    metrics::inc_counter_vec(&metrics::DISK_DB_WRITE_COUNT, &[column.into()]);
                    let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                        TableDefinition::new(column.into());

                    let mut table = tx.open_table(table_definition)?;
                    table.insert(key.as_slice(), value.as_slice())?;
                    drop(table);
                }

                KeyValueStoreOp::DeleteKey(column, key) => {
                    metrics::inc_counter_vec(&metrics::DISK_DB_DELETE_COUNT, &[column.into()]);
                    let _timer = metrics::start_timer(&metrics::DISK_DB_DELETE_TIMES);
                    let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                        TableDefinition::new(column.into());

                    let mut table = tx.open_table(table_definition)?;
                    table.remove(key.as_slice())?;
                    drop(table);
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Compact all values in the states and states flag columns.
    pub fn compact(&self) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::DISK_DB_COMPACT_TIMES);
        let mut open_db = self.db.write();
        let mut_db = open_db.borrow_mut();
        mut_db.compact().map_err(Into::into).map(|_| ())
    }

    pub fn iter_column_keys_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnKeyIter<K> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(column.into());

        let result = (|| {
            let open_db = self.db.read();
            let read_txn = open_db.begin_read()?;
            let table = read_txn.open_table(table_definition)?;
            let range = table.range(from..)?;
            Ok(range.map(move |res| {
                let (key, _) = res?;
                metrics::inc_counter_vec(&metrics::DISK_DB_KEY_READ_COUNT, &[column.into()]);
                metrics::inc_counter_vec_by(
                    &metrics::DISK_DB_KEY_READ_BYTES,
                    &[column.into()],
                    key.value().len() as u64,
                );
                K::from_bytes(key.value())
            }))
        })();

        match result {
            Ok(iter) => Box::new(iter),
            Err(err) => Box::new(std::iter::once(Err(err))),
        }
    }

    /// Iterate through all keys and values in a particular column.
    pub fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<K> {
        self.iter_column_keys_from(column, &vec![0; column.key_size()])
    }

    pub fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<K> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(column.into());

        let result = (|| {
            let open_db = self.db.read();
            let read_txn = open_db.begin_read()?;
            let table = read_txn.open_table(table_definition)?;
            let range = table.range(from..)?;

            Ok(range
                .take_while(move |res| match res.as_ref() {
                    Ok((_, _)) => true,
                    Err(_) => false,
                })
                .map(move |res| {
                    let (key, value) = res?;
                    metrics::inc_counter_vec(&metrics::DISK_DB_READ_COUNT, &[column.into()]);
                    metrics::inc_counter_vec_by(
                        &metrics::DISK_DB_READ_BYTES,
                        &[column.into()],
                        value.value().len() as u64,
                    );
                    Ok((K::from_bytes(key.value())?, value.value().to_vec()))
                }))
        })();

        match result {
            Ok(iter) => Box::new(iter),
            Err(err) => Box::new(std::iter::once(Err(err))),
        }
    }

    pub fn iter_column<K: Key>(&self, column: DBColumn) -> ColumnIter<K> {
        self.iter_column_from(column, &vec![0; column.key_size()])
    }

    pub fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        let open_db = self.db.read();
        let mut tx = open_db.begin_write()?;

        tx.set_durability(redb::Durability::None);

        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(col.into());

        let mut table = tx.open_table(table_definition)?;
        table.retain(|key, _| !ops.contains(key))?;

        drop(table);
        tx.commit()?;
        Ok(())
    }

    pub fn delete_if(
        &self,
        column: DBColumn,
        mut f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let open_db = self.db.read();
        let mut tx = open_db.begin_write()?;

        tx.set_durability(redb::Durability::None);

        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(column.into());

        let mut table = tx.open_table(table_definition)?;
        table.retain(|_, value| !f(value).unwrap_or(false))?;

        drop(table);
        tx.commit()?;
        Ok(())
    }
}
