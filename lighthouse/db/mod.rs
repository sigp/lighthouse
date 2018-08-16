extern crate rocksdb;

use std::fs;
use std::path::Path;
pub use self::rocksdb::DB;

pub fn open_db(path: &Path) -> DB {
    let db_path = path.join("rocksdb");
    fs::create_dir_all(&db_path)
        .expect(&format!("Unable to create {:?}", &db_path));
    let db = DB::open_default(db_path.join("lighthouse.rdb"))
        .expect("Unable to open local database.");
    db
}
