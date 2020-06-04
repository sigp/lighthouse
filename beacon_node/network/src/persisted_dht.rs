use eth2_libp2p::Enr;
use rlp;
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, Store, StoreItem};
use types::{EthSpec, Hash256};

/// 32-byte key for accessing the `DhtEnrs`.
pub const DHT_DB_KEY: &str = "PERSISTEDDHTPERSISTEDDHTPERSISTE";

pub fn load_dht<T: Store<E>, E: EthSpec>(store: Arc<T>) -> Vec<Enr> {
    // Load DHT from store
    let key = Hash256::from_slice(&DHT_DB_KEY.as_bytes());
    match store.get_item(&key) {
        Ok(Some(p)) => {
            let p: PersistedDht = p;
            p.enrs
        }
        _ => Vec::new(),
    }
}

/// Attempt to persist the ENR's in the DHT to `self.store`.
pub fn persist_dht<T: Store<E>, E: EthSpec>(
    store: Arc<T>,
    enrs: Vec<Enr>,
) -> Result<(), store::Error> {
    let key = Hash256::from_slice(&DHT_DB_KEY.as_bytes());
    store.put_item(&key, &PersistedDht { enrs })?;
    Ok(())
}

/// Wrapper around DHT for persistence to disk.
pub struct PersistedDht {
    pub enrs: Vec<Enr>,
}

impl StoreItem for PersistedDht {
    fn db_column() -> DBColumn {
        DBColumn::DhtEnrs
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        rlp::encode_list(&self.enrs)
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let rlp = rlp::Rlp::new(bytes);
        let enrs: Vec<Enr> = rlp
            .as_list()
            .map_err(|e| StoreError::RlpError(format!("{}", e)))?;
        Ok(PersistedDht { enrs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth2_libp2p::Enr;
    use std::str::FromStr;
    use std::sync::Arc;
    use store::{MemoryStore, Store};
    use types::Hash256;
    use types::MinimalEthSpec;
    #[test]
    fn test_persisted_dht() {
        let store = Arc::new(MemoryStore::<MinimalEthSpec>::open());
        let enrs = vec![Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap()];
        let key = Hash256::from_slice(&DHT_DB_KEY.as_bytes());
        store
            .put_item(&key, &PersistedDht { enrs: enrs.clone() })
            .unwrap();
        let dht: PersistedDht = store.get_item(&key).unwrap().unwrap();
        assert_eq!(dht.enrs, enrs);
    }
}
