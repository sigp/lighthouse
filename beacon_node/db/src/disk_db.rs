extern crate rocksdb;

use super::rocksdb::Error as RocksError;
use super::rocksdb::{Options, DB};
use super::stores::COLUMNS;
use super::{ClientDB, DBError, DBValue};
use std::fs;
use std::path::Path;

/// A on-disk database which implements the ClientDB trait.
///
/// This implementation uses RocksDB with default options.
pub struct DiskDB {
    db: DB,
}

impl DiskDB {
    /// Open the RocksDB database, optionally supplying columns if required.
    ///
    /// The RocksDB database will be contained in a directory titled
    /// "database" in the supplied path.
    ///
    /// # Panics
    ///
    /// Panics if the database is unable to be created.
    pub fn open(path: &Path, columns: Option<&[&str]>) -> Self {
        // Rocks options.
        let mut options = Options::default();
        options.create_if_missing(true);

        // Ensure the path exists.
        fs::create_dir_all(&path).unwrap_or_else(|_| panic!("Unable to create {:?}", &path));
        let db_path = path.join("database");

        let columns = columns.unwrap_or(&COLUMNS);

        if db_path.exists() {
            Self {
                db: DB::open_cf(&options, db_path, &COLUMNS)
                    .expect("Unable to open local database"),
            }
        } else {
            let mut db = Self {
                db: DB::open(&options, db_path).expect("Unable to open local database"),
            };

            for cf in columns {
                db.create_col(cf).unwrap();
            }

            db
        }
    }

    /// Create a RocksDB column family. Corresponds to the
    /// `create_cf()` function on the RocksDB API.
    #[allow(dead_code)]
    fn create_col(&mut self, col: &str) -> Result<(), DBError> {
        match self.db.create_cf(col, &Options::default()) {
            Err(e) => Err(e.into()),
            Ok(_) => Ok(()),
        }
    }
}

impl From<RocksError> for DBError {
    fn from(e: RocksError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl ClientDB for DiskDB {
    /// Get the value for some key on some column.
    ///
    /// Corresponds to the `get_cf()` method on the RocksDB API.
    /// Will attempt to get the `ColumnFamily` and return an Err
    /// if it fails.
    fn get(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, DBError> {
        match self.db.cf_handle(col) {
            None => Err(DBError {
                message: "Unknown column".to_string(),
            }),
            Some(handle) => match self.db.get_cf(handle, key)? {
                None => Ok(None),
                Some(db_vec) => Ok(Some(DBValue::from(&*db_vec))),
            },
        }
    }

    /// Set some value for some key on some column.
    ///
    /// Corresponds to the `cf_handle()` method on the RocksDB API.
    /// Will attempt to get the `ColumnFamily` and return an Err
    /// if it fails.
    fn put(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), DBError> {
        match self.db.cf_handle(col) {
            None => Err(DBError {
                message: "Unknown column".to_string(),
            }),
            Some(handle) => self.db.put_cf(handle, key, val).map_err(Into::into),
        }
    }

    /// Return true if some key exists in some column.
    fn exists(&self, col: &str, key: &[u8]) -> Result<bool, DBError> {
        /*
         * I'm not sure if this is the correct way to read if some
         * block exists. Naively I would expect this to unncessarily
         * copy some data, but I could be wrong.
         */
        match self.db.cf_handle(col) {
            None => Err(DBError {
                message: "Unknown column".to_string(),
            }),
            Some(handle) => Ok(self.db.get_cf(handle, key)?.is_some()),
        }
    }

    /// Delete the value for some key on some column.
    ///
    /// Corresponds to the `delete_cf()` method on the RocksDB API.
    /// Will attempt to get the `ColumnFamily` and return an Err
    /// if it fails.
    fn delete(&self, col: &str, key: &[u8]) -> Result<(), DBError> {
        match self.db.cf_handle(col) {
            None => Err(DBError {
                message: "Unknown column".to_string(),
            }),
            Some(handle) => {
                self.db.delete_cf(handle, key)?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ClientDB;
    use super::*;
    use std::sync::Arc;
    use std::{env, fs, thread};

    #[test]
    #[ignore]
    fn test_rocksdb_can_use_db() {
        let pwd = env::current_dir().unwrap();
        let path = pwd.join("testdb_please_remove");
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        let col_name: &str = "TestColumn";
        let column_families = vec![col_name];

        let mut db = DiskDB::open(&path, None);

        for cf in column_families {
            db.create_col(&cf).unwrap();
        }

        let db = Arc::new(db);

        let thread_count = 10;
        let write_count = 10;

        // We're execting the product of these numbers to fit in one byte.
        assert!(thread_count * write_count <= 255);

        let mut handles = vec![];
        for t in 0..thread_count {
            let wc = write_count;
            let db = db.clone();
            let col = col_name.clone();
            let handle = thread::spawn(move || {
                for w in 0..wc {
                    let key = (t * w) as u8;
                    let val = 42;
                    db.put(&col, &vec![key], &vec![val]).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        for t in 0..thread_count {
            for w in 0..write_count {
                let key = (t * w) as u8;
                let val = db.get(&col_name, &vec![key]).unwrap().unwrap();
                assert_eq!(vec![42], val);
            }
        }
        fs::remove_dir_all(&path).unwrap();
    }
}
