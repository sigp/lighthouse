use std::collections::{ HashSet, HashMap };
use std::sync::RwLock;
use super::blake2::blake2b::blake2b;
use super::{
    ClientDB,
    DBValue,
    DBError
};

type DBHashMap = HashMap<Vec<u8>, Vec<u8>>;
type ColumnHashSet = HashSet<String>;

pub struct MemoryDB {
    db: RwLock<DBHashMap>,
    known_columns: RwLock<ColumnHashSet>
}

impl MemoryDB {
    pub fn open(columns: Option<&[&str]>) -> Self {
        let mut db: DBHashMap = HashMap::new();
        let mut known_columns: ColumnHashSet = HashSet::new();
        if let Some(columns) = columns {
            for col in columns {
                known_columns.insert(col.to_string());
            }
        }
        Self {
            db: RwLock::new(db),
            known_columns: RwLock::new(known_columns),
        }
    }

    fn get_key_for_col(col: &str, key: &[u8]) -> Vec<u8> {
        blake2b(32, col.as_bytes(), key).as_bytes().to_vec()
    }
}

impl ClientDB for MemoryDB {
    fn create_col(&mut self, col: &str)
        -> Result<(), DBError>
    {
        Ok(())      // This field is not used. Will remove from trait.
    }

    fn get(&self, col: &str, key: &[u8])
        -> Result<Option<DBValue>, DBError>
    {
        // Panic if the DB locks are poisoned.
        let db = self.db.read().unwrap();
        let known_columns = self.known_columns.read().unwrap();

        match known_columns.contains(&col.to_string()) {
            false => Err(DBError{ message: "Unknown column".to_string() }),
            true => {
                let column_key = MemoryDB::get_key_for_col(col, key);
                Ok(db.get(&column_key).and_then(|val| Some(val.clone())))
            }
        }
    }

    fn put(&self, col: &str, key: &[u8], val: &[u8])
        -> Result<(), DBError>
    {
        // Panic if the DB locks are poisoned.
        let mut db = self.db.write().unwrap();
        let known_columns = self.known_columns.read().unwrap();

        match known_columns.contains(&col.to_string()) {
            false => Err(DBError{ message: "Unknown column".to_string() }),
            true => {
                let column_key = MemoryDB::get_key_for_col(col, key);
                db.insert(column_key, val.to_vec());
                Ok(())
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ClientDB;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_memorydb_column_access() {
        let col_a: &str = "ColumnA";
        let col_b: &str = "ColumnB";

        let column_families = vec![
            col_a,
            col_b,
        ];

        let db = MemoryDB::open(Some(&column_families));

        /*
         * Testing that if we write to the same key in different columns that
         * there is not an overlap.
         */
        db.put(col_a, "same".as_bytes(), "cat".as_bytes()).unwrap();
        db.put(col_b, "same".as_bytes(), "dog".as_bytes()).unwrap();

        assert_eq!(db.get(col_a, "same".as_bytes()).unwrap().unwrap(), "cat".as_bytes());
        assert_eq!(db.get(col_b, "same".as_bytes()).unwrap().unwrap(), "dog".as_bytes());


    }

    #[test]
    fn test_memorydb_unknown_column_access() {
        let col_a: &str = "ColumnA";
        let col_x: &str = "ColumnX";

        let column_families = vec![
            col_a,
            // col_x is excluded on purpose
        ];

        let db = MemoryDB::open(Some(&column_families));

        /*
         * Test that we get errors when using undeclared columns
         */
        assert!(db.put(col_a, "cats".as_bytes(), "lol".as_bytes()).is_ok());
        assert!(db.put(col_x, "cats".as_bytes(), "lol".as_bytes()).is_err());

        assert!(db.get(col_a, "cats".as_bytes()).is_ok());
        assert!(db.get(col_x, "cats".as_bytes()).is_err());
    }

    #[test]
    fn test_memorydb_threading() {
        let col_name: &str = "TestColumn";
        let column_families = vec![col_name];

        let db = Arc::new(MemoryDB::open(Some(&column_families)));

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
    }
}
