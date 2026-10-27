use crate::{ColumnIter, ColumnKeyIter, Key, metrics};
use crate::{DBColumn, Error, KeyValueStoreOp};
use parking_lot::RwLock;
use redb::TableDefinition;
use std::collections::HashSet;
use std::{borrow::BorrowMut, path::Path};
use strum::IntoEnumIterator;

use super::interface::WriteOptions;

pub const DB_FILE_NAME: &str = "database.redb";

pub struct Redb {
    db: RwLock<redb::Database>,
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

impl Redb {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let db_file = path.join(DB_FILE_NAME);
        let db = redb::Database::create(db_file)?;

        // Create all tables in a single transaction so that the allocator state is only written
        // once (see `begin_write`).
        let tx = Self::begin_write(&db)?;
        for column in DBColumn::iter() {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(column.into());
            tx.open_table(table_definition)?;
        }
        tx.commit()?;

        Ok(Self { db: db.into() })
    }

    /// Begin a write transaction with redb's quick-repair enabled.
    ///
    /// Quick-repair persists the allocator state with every commit, so that the database can be
    /// reopened quickly after an unclean shutdown. Without it, redb has to re-read the entire
    /// database file to rebuild the allocator state, which can take hours for large databases.
    ///
    /// Every write transaction must use quick-repair: a durable commit without it deletes the
    /// saved allocator state.
    fn begin_write(db: &redb::Database) -> Result<redb::WriteTransaction, Error> {
        let mut tx = db.begin_write()?;
        tx.set_quick_repair(true);
        Ok(tx)
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
        let mut tx = Self::begin_write(&open_db)?;
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
        let tx = Self::begin_write(&open_db)?;
        let mut table = tx.open_table(table_definition)?;
        metrics::inc_counter_vec(&metrics::DISK_DB_DELETE_COUNT, &[col.into()]);

        table.remove(key).map(|_| ())?;
        drop(table);
        tx.commit().map_err(Into::into)
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        let open_db = self.db.read();
        let mut tx = Self::begin_write(&open_db)?;
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
        mut_db.compact()?;

        // Compaction commits without quick-repair, which deletes the saved allocator state.
        // Re-save it so that an unclean shutdown before the next write doesn't need a full repair.
        Self::begin_write(mut_db)?.commit()?;
        Ok(())
    }

    pub fn iter_column_keys_from<K: Key>(
        &self,
        column: DBColumn,
        from: &[u8],
    ) -> ColumnKeyIter<'_, K> {
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
    pub fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        self.iter_column_keys_from(column, &vec![0; column.key_size()])
    }

    pub fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
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

    pub fn iter_column<K: Key>(&self, column: DBColumn) -> ColumnIter<'_, K> {
        self.iter_column_from(column, &vec![0; column.key_size()])
    }

    pub fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        let open_db = self.db.read();
        let mut tx = Self::begin_write(&open_db)?;

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
        let mut tx = Self::begin_write(&open_db)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    /// Copy the database file as it currently is on disk, which is what a new process would see
    /// if this one crashed now, and check that the copy opens without a full repair.
    #[track_caller]
    fn copy_and_open_without_repair(dir: &Path) -> TempDir {
        let copy_dir = tempdir().unwrap();
        std::fs::copy(dir.join(DB_FILE_NAME), copy_dir.path().join(DB_FILE_NAME)).unwrap();

        // redb invokes the repair callback before starting a full repair (which re-reads the whole
        // file), and aborting it fails the open.
        redb::Builder::new()
            .set_repair_callback(|session| session.abort())
            .create(copy_dir.path().join(DB_FILE_NAME))
            .expect("full repair should not be required");
        copy_dir
    }

    /// Regression test for https://github.com/sigp/lighthouse/issues/10440.
    ///
    /// Close the database uncleanly by never running `Drop` for the `redb::Database`, as happens
    /// after a crash, and check that it can be reopened without a full repair.
    #[test]
    fn reopen_after_unclean_shutdown_without_repair() {
        let col = DBColumn::BeaconBlock;
        let key = |i: u64| i.to_be_bytes().to_vec();
        let value = |i: u64| i.to_be_bytes().repeat(128);

        let dir = tempdir().unwrap();
        let db = Redb::open(dir.path()).unwrap();
        copy_and_open_without_repair(dir.path());

        // Only the most recent durable commit determines whether a full repair is needed, so check
        // after every write path.
        db.do_atomically(
            (0..1024)
                .map(|i| KeyValueStoreOp::PutKeyValue(col, key(i), value(i)))
                .collect(),
        )
        .unwrap();
        copy_and_open_without_repair(dir.path());

        // These deletes are non-durable, so they are persisted by the next durable commit.
        let (key_0, key_1, value_2) = (key(0), key(1), value(2));
        db.delete_batch(col, HashSet::from([key_0.as_slice(), key_1.as_slice()]))
            .unwrap();
        db.delete_if(col, |val| Ok(val == value_2)).unwrap();
        copy_and_open_without_repair(dir.path());

        db.key_delete(col, &key(3)).unwrap();
        copy_and_open_without_repair(dir.path());

        db.do_atomically(vec![KeyValueStoreOp::DeleteKey(col, key(4))])
            .unwrap();
        copy_and_open_without_repair(dir.path());

        db.put_bytes(col, &key(5), b"put").unwrap();
        copy_and_open_without_repair(dir.path());

        db.put_bytes_sync(col, &key(6), b"put_sync").unwrap();
        copy_and_open_without_repair(dir.path());

        db.compact().unwrap();
        copy_and_open_without_repair(dir.path());

        // Close uncleanly: `Drop for redb::Database` writes the allocator state, so never run it.
        // The leaked database keeps redb's exclusive file lock, so reopen a copy of the file.
        std::mem::forget(db);
        let reopen_dir = copy_and_open_without_repair(dir.path());

        // All writes made before the unclean shutdown must have been persisted.
        let db = Redb::open(reopen_dir.path()).unwrap();
        for i in 0..5 {
            assert_eq!(db.get_bytes(col, &key(i)).unwrap(), None, "key {i}");
        }
        assert_eq!(db.get_bytes(col, &key(5)).unwrap(), Some(b"put".to_vec()));
        assert_eq!(
            db.get_bytes(col, &key(6)).unwrap(),
            Some(b"put_sync".to_vec())
        );
        for i in 7..1024 {
            assert_eq!(
                db.get_bytes(col, &key(i)).unwrap(),
                Some(value(i)),
                "key {i}"
            );
        }
    }
}
