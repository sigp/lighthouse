use crate::eth1_chain::SszEth1;
use eth1::{BlockCache, SszDepositCacheV1, SszDepositCacheV13, SszEth1CacheV1, SszEth1CacheV13};
use ssz::{Decode, Encode};
use state_processing::common::DepositDataTree;
use store::Error;
use types::DEPOSIT_TREE_DEPTH;

pub fn update_eth1_cache(persisted_eth1_v1: SszEth1) -> Result<SszEth1, Error> {
    if persisted_eth1_v1.use_dummy_backend {
        // backend_bytes is empty when using dummy backend
        return Ok(persisted_eth1_v1);
    }

    let SszEth1 {
        use_dummy_backend,
        backend_bytes,
    } = persisted_eth1_v1;

    let ssz_eth1_cache_v1 = SszEth1CacheV1::from_ssz_bytes(&backend_bytes)?;
    let SszEth1CacheV1 {
        block_cache,
        deposit_cache: deposit_cache_v1,
        last_processed_block,
    } = ssz_eth1_cache_v1;

    let SszDepositCacheV1 {
        logs,
        leaves,
        deposit_contract_deploy_block,
        deposit_roots,
    } = deposit_cache_v1;

    let deposit_cache_v13 = SszDepositCacheV13 {
        logs,
        leaves,
        deposit_contract_deploy_block,
        finalized_deposit_count: 0,
        finalized_block_height: deposit_contract_deploy_block.saturating_sub(1),
        deposit_tree_snapshot: None,
        deposit_roots,
    };

    let ssz_eth1_cache_v13 = SszEth1CacheV13 {
        block_cache,
        deposit_cache: deposit_cache_v13,
        last_processed_block,
    };

    let persisted_eth1_v13 = SszEth1 {
        use_dummy_backend,
        backend_bytes: ssz_eth1_cache_v13.as_ssz_bytes(),
    };

    Ok(persisted_eth1_v13)
}

pub fn downgrade_eth1_cache(persisted_eth1_v13: SszEth1) -> Result<Option<SszEth1>, Error> {
    if persisted_eth1_v13.use_dummy_backend {
        // backend_bytes is empty when using dummy backend
        return Ok(Some(persisted_eth1_v13));
    }

    let SszEth1 {
        use_dummy_backend,
        backend_bytes,
    } = persisted_eth1_v13;

    let ssz_eth1_cache_v13 = SszEth1CacheV13::from_ssz_bytes(&backend_bytes)?;
    let SszEth1CacheV13 {
        block_cache,
        deposit_cache: deposit_cache_v13,
        last_processed_block,
    } = ssz_eth1_cache_v13;

    let SszDepositCacheV13 {
        logs,
        leaves,
        deposit_contract_deploy_block,
        finalized_deposit_count,
        finalized_block_height: _,
        deposit_tree_snapshot,
        deposit_roots,
    } = deposit_cache_v13;

    if finalized_deposit_count == 0 && deposit_tree_snapshot.is_none() {
        // This tree was never finalized and can be directly downgraded to v1 without re-initializing
        let deposit_cache_v1 = SszDepositCacheV1 {
            logs,
            leaves,
            deposit_contract_deploy_block,
            deposit_roots,
        };
        let ssz_eth1_cache_v1 = SszEth1CacheV1 {
            block_cache,
            deposit_cache: deposit_cache_v1,
            last_processed_block,
        };
        return Ok(Some(SszEth1 {
            use_dummy_backend,
            backend_bytes: ssz_eth1_cache_v1.as_ssz_bytes(),
        }));
    }
    // deposit cache was finalized; can't downgrade
    Ok(None)
}

pub fn reinitialized_eth1_cache_v13(deposit_contract_deploy_block: u64) -> SszEth1 {
    let empty_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);
    let deposit_cache_v13 = SszDepositCacheV13 {
        logs: vec![],
        leaves: vec![],
        deposit_contract_deploy_block,
        finalized_deposit_count: 0,
        finalized_block_height: deposit_contract_deploy_block.saturating_sub(1),
        deposit_tree_snapshot: empty_tree.get_snapshot(),
        deposit_roots: vec![empty_tree.root()],
    };

    let ssz_eth1_cache_v13 = SszEth1CacheV13 {
        block_cache: BlockCache::default(),
        deposit_cache: deposit_cache_v13,
        last_processed_block: None,
    };

    SszEth1 {
        use_dummy_backend: false,
        backend_bytes: ssz_eth1_cache_v13.as_ssz_bytes(),
    }
}

pub fn reinitialized_eth1_cache_v1(deposit_contract_deploy_block: u64) -> SszEth1 {
    let empty_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);
    let deposit_cache_v1 = SszDepositCacheV1 {
        logs: vec![],
        leaves: vec![],
        deposit_contract_deploy_block,
        deposit_roots: vec![empty_tree.root()],
    };

    let ssz_eth1_cache_v1 = SszEth1CacheV1 {
        block_cache: BlockCache::default(),
        deposit_cache: deposit_cache_v1,
        last_processed_block: None,
    };

    SszEth1 {
        use_dummy_backend: false,
        backend_bytes: ssz_eth1_cache_v1.as_ssz_bytes(),
    }
}
