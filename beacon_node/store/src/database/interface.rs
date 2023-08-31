pub enum Environment {

}

pub enum Database {

}

pub enum RwTransaction {

}

pub enum Options {

}

impl Environment {
    pub fn new(config: &StoreConfig) {
    }

    pub fn create_database(&self) {
    }

    pub fn create_rw_transaction(&self) {
    }
}

impl RwTransaction {
    pub fn put_with_options(&self) {
    }

    pub fn get(&self) {
    }

    pub fn delete(&self) { 
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) {
    }

    pub fn compact(&self) {
    }

    pub fn iter_column(&self) {
    }
}