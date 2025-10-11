use crate::BeaconForkChoiceStore;
use crate::beacon_chain::BeaconChainTypes;
use crate::persisted_fork_choice::PersistedForkChoiceV17;
use crate::schema_change::StoreError;
use crate::test_utils::{BEACON_CHAIN_DB_KEY, FORK_CHOICE_DB_KEY, PersistedBeaconChain};
use fork_choice::{ForkChoice, ResetPayloadStatuses};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use store::{DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem};
use tracing::{debug, info};
use types::{Hash256, Slot};

/// Dummy value to use for the canonical head block root, see below.
pub const DUMMY_CANONICAL_HEAD_BLOCK_ROOT: Hash256 = Hash256::repeat_byte(0xff);

pub fn upgrade_to_v23<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!("Upgrading DB schema from v22 to v23");

    // 1) Set the head-tracker to empty
    let Some(persisted_beacon_chain_v22) =
        db.get_item::<PersistedBeaconChainV22>(&BEACON_CHAIN_DB_KEY)?
    else {
        return Err(Error::MigrationError(
            "No persisted beacon chain found in DB. Datadir could be incorrect or DB could be corrupt".to_string()
        ));
    };

    let persisted_beacon_chain = PersistedBeaconChain {
        genesis_block_root: persisted_beacon_chain_v22.genesis_block_root,
    };

    let mut ops = vec![persisted_beacon_chain.as_kv_store_op(BEACON_CHAIN_DB_KEY)];

    // 2) Wipe out all state temporary flags. While un-used in V23, if there's a rollback we could
    // end-up with an inconsistent DB.
    for state_root_result in db
        .hot_db
        .iter_column_keys::<Hash256>(DBColumn::BeaconStateTemporary)
    {
        let state_root = state_root_result?;
        debug!(
            ?state_root,
            "Deleting temporary state on v23 schema migration"
        );
        ops.push(KeyValueStoreOp::DeleteKey(
            DBColumn::BeaconStateTemporary,
            state_root.as_slice().to_vec(),
        ));

        // We also delete the temporary states themselves. Although there are known issue with
        // temporary states and this could lead to DB corruption, we will only corrupt the DB in
        // cases where the DB would be corrupted by restarting on v7.0.x. We consider these DBs
        // "too far gone". Deleting here has the advantage of not generating warnings about
        // disjoint state DAGs in the v24 upgrade, or the first pruning after migration.
        ops.push(KeyValueStoreOp::DeleteKey(
            DBColumn::BeaconState,
            state_root.as_slice().to_vec(),
        ));
        ops.push(KeyValueStoreOp::DeleteKey(
            DBColumn::BeaconStateSummary,
            state_root.as_slice().to_vec(),
        ));
    }

    Ok(ops)
}

pub fn downgrade_from_v23<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let Some(persisted_beacon_chain) = db.get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)?
    else {
        // The `PersistedBeaconChain` must exist if fork choice exists.
        return Err(Error::MigrationError(
            "No persisted beacon chain found in DB. Datadir could be incorrect or DB could be corrupt".to_string(),
        ));
    };

    // Recreate head-tracker from fork choice.
    let Some(persisted_fork_choice) = db.get_item::<PersistedForkChoiceV17>(&FORK_CHOICE_DB_KEY)?
    else {
        // Fork choice should exist if the database exists.
        return Err(Error::MigrationError(
            "No fork choice found in DB".to_string(),
        ));
    };

    // We use dummy roots for the justified states because we can source the balances from the v17
    // persited fork choice. The justified state root isn't required to look up the justified state's
    // balances (as it would be in V28). This fork choice object with corrupt state roots SHOULD NOT
    // be written to disk.
    let dummy_justified_state_root = Hash256::repeat_byte(0x66);
    let dummy_unrealized_justified_state_root = Hash256::repeat_byte(0x77);

    let fc_store = BeaconForkChoiceStore::from_persisted_v17(
        persisted_fork_choice.fork_choice_store_v17,
        dummy_justified_state_root,
        dummy_unrealized_justified_state_root,
        db.clone(),
    )
    .map_err(|e| {
        Error::MigrationError(format!(
            "Error loading fork choice store from persisted: {e:?}"
        ))
    })?;

    // Doesn't matter what policy we use for invalid payloads, as our head calculation just
    // considers descent from finalization.
    let reset_payload_statuses = ResetPayloadStatuses::OnlyWithInvalidPayload;
    let fork_choice = ForkChoice::from_persisted(
        persisted_fork_choice.fork_choice_v17.try_into()?,
        reset_payload_statuses,
        fc_store,
        &db.spec,
    )
    .map_err(|e| {
        Error::MigrationError(format!("Error loading fork choice from persisted: {e:?}"))
    })?;

    let heads = fork_choice
        .proto_array()
        .heads_descended_from_finalization::<T::EthSpec>();

    let head_roots = heads.iter().map(|node| node.root).collect();
    let head_slots = heads.iter().map(|node| node.slot).collect();

    let persisted_beacon_chain_v22 = PersistedBeaconChainV22 {
        _canonical_head_block_root: DUMMY_CANONICAL_HEAD_BLOCK_ROOT,
        genesis_block_root: persisted_beacon_chain.genesis_block_root,
        ssz_head_tracker: SszHeadTracker {
            roots: head_roots,
            slots: head_slots,
        },
    };

    let ops = vec![persisted_beacon_chain_v22.as_kv_store_op(BEACON_CHAIN_DB_KEY)];

    Ok(ops)
}

/// Helper struct that is used to encode/decode the state of the `HeadTracker` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct SszHeadTracker {
    roots: Vec<Hash256>,
    slots: Vec<Slot>,
}

#[derive(Clone, Encode, Decode)]
pub struct PersistedBeaconChainV22 {
    /// This value is ignored to resolve the issue described here:
    ///
    /// https://github.com/sigp/lighthouse/pull/1639
    ///
    /// Its removal is tracked here:
    ///
    /// https://github.com/sigp/lighthouse/issues/1784
    pub _canonical_head_block_root: Hash256,
    pub genesis_block_root: Hash256,
    /// DEPRECATED
    pub ssz_head_tracker: SszHeadTracker,
}

impl StoreItem for PersistedBeaconChainV22 {
    fn db_column() -> DBColumn {
        DBColumn::BeaconChain
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
