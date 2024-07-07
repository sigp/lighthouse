use lighthouse_network::Enr;
use std::{str::FromStr, sync::Arc};
use store::{DBColumn, Error as StoreError, HotColdDB, ItemStore, StoreItem};
use types::{EthSpec, Hash256};

/// 32-byte key for accessing the `DhtEnrs`. All zero because `DhtEnrs` has its own column.
pub const DHT_DB_KEY: Hash256 = Hash256::zero();

pub fn load_dht<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
) -> Vec<Enr> {
    // Load DHT from store
    match store.get_item(&DHT_DB_KEY) {
        Ok(Some(p)) => {
            let p: PersistedDht = p;
            p.enrs
        }
        _ => Vec::new(),
    }
}

/// Attempt to persist the ENR's in the DHT to `self.store`.
pub fn persist_dht<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
    enrs: Vec<Enr>,
) -> Result<(), store::Error> {
    store.put_item(&DHT_DB_KEY, &PersistedDht { enrs })
}

/// Attempts to clear any DHT entries.
pub fn clear_dht<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: Arc<HotColdDB<E, Hot, Cold>>,
) -> Result<(), store::Error> {
    store.hot_db.delete::<PersistedDht>(&DHT_DB_KEY)
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
        let mut saved_enr: Vec<u8> = vec![];
        for enr in &self.enrs {
            saved_enr.extend_from_slice(enr.to_base64().replace("enr:", "").as_bytes());
            saved_enr.push(0x00);
        }
        saved_enr
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut enrs = vec![];

        let split = bytes.split(|b| *b == 0x00);

        for enr in split {
            let string = String::from_utf8(enr.to_vec()).map_err(|_| StoreError::InvalidBytes)?;
            let enr =
                Enr::from_str(&format!("enr:{}", string)).map_err(|_| StoreError::InvalidBytes)?;
            enrs.push(enr);
        }

        Ok(PersistedDht { enrs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use store::config::StoreConfig;
    use store::MemoryStore;
    use types::{ChainSpec, MinimalEthSpec};
    #[test]
    fn test_persisted_dht() {
        let log = NullLoggerBuilder.build().unwrap();
        let store: HotColdDB<
            MinimalEthSpec,
            MemoryStore<MinimalEthSpec>,
            MemoryStore<MinimalEthSpec>,
        > = HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log).unwrap();
        let enrs = vec![Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap()];
        store
            .put_item(&DHT_DB_KEY, &PersistedDht { enrs: enrs.clone() })
            .unwrap();
        let dht: PersistedDht = store.get_item(&DHT_DB_KEY).unwrap().unwrap();
        assert_eq!(dht.enrs, enrs);
    }
}
