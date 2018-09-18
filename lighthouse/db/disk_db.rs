extern crate rocksdb;

use std::fs;
use std::path::Path;
use super::rocksdb::{
    DB,
    Options,
};
use super::rocksdb::Error as RocksError;
use super::{
    ClientDB,
    DBValue,
    DBError
};

pub struct DiskDB {
    db: DB,
}

impl DiskDB {
    pub fn open(path: &Path, columns: Option<&[&str]>) -> Self {
        /*
         * Initialise the options
         */
        let mut options = Options::default();
        options.create_if_missing(true);

        /*
         * Initialise the path
         */
        fs::create_dir_all(&path)
            .expect(&format!("Unable to create {:?}", &path));
        let db_path = path.join("database");

        /*
         * Open the database
         */
        let db = match columns {
            None => DB::open(&options, db_path),
            Some(columns) => DB::open_cf(&options, db_path, columns)
        }.expect("Unable to open local database");;

        Self {
            db,
        }
    }
}

impl From<RocksError> for DBError {
    fn from(e: RocksError) -> Self {
        Self { message: e.to_string() }
    }
}

impl ClientDB for DiskDB {
    fn create_col(&mut self, col: &str)
        -> Result<(), DBError>
    {
        match self.db.create_cf(col, &Options::default()) {
            Err(e) => Err(e.into()),
            Ok(_) => Ok(())
        }
    }

    fn get(&self, col: &str, key: &[u8])
        -> Result<Option<DBValue>, DBError>
    {
        match self.db.cf_handle(col) {
            None => Err(DBError{ message: "Unknown column".to_string() }),
            Some(handle) => {
                match self.db.get_cf(handle, key)? {
                    None => Ok(None),
                    Some(db_vec) => Ok(Some(DBValue::from(&*db_vec)))
                }
            }
        }
    }

    fn put(&self, col: &str, key: &[u8], val: &[u8])
        -> Result<(), DBError>
    {
        match self.db.cf_handle(col) {
            None => Err(DBError{ message: "Unknown column".to_string() }),
            Some(handle) => self.db.put_cf(handle, key, val).map_err(|e| e.into())
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ClientDB;
    use std::{ env, fs, thread };
    use std::sync::Arc;

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
