use crate::{
    BeaconChain, BeaconChainTypes, BeaconForkChoiceStore, PersistedForkChoiceStoreV17,
    beacon_chain::FORK_CHOICE_DB_KEY,
    persisted_fork_choice::{PersistedForkChoiceV17, PersistedForkChoiceV28},
    summaries_dag::{DAGStateSummary, StateSummariesDAG},
};
use fork_choice::{ForkChoice, ForkChoiceStore, ResetPayloadStatuses};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};
use tracing::{info, warn};
use types::{EthSpec, Hash256};

/// Upgrade `PersistedForkChoice` from V17 to V28.
pub fn upgrade_to_v28<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let Some(persisted_fork_choice_v17) =
        db.get_item::<PersistedForkChoiceV17>(&FORK_CHOICE_DB_KEY)?
    else {
        warn!("No fork choice found to upgrade to v28");
        return Ok(vec![]);
    };

    // Load state DAG in order to compute justified checkpoint roots.
    let state_summaries_dag = {
        let state_summaries = db
            .load_hot_state_summaries()?
            .into_iter()
            .map(|(state_root, summary)| (state_root, summary.into()))
            .collect::<Vec<(Hash256, DAGStateSummary)>>();

        StateSummariesDAG::new(state_summaries).map_err(|e| {
            Error::MigrationError(format!("Error loading state summaries DAG: {e:?}"))
        })?
    };

    // Determine the justified state roots.
    let justified_checkpoint = persisted_fork_choice_v17
        .fork_choice_store_v17
        .justified_checkpoint;
    let justified_block_root = justified_checkpoint.root;
    let justified_slot = justified_checkpoint
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    let justified_state_root = state_summaries_dag
        .state_root_at_slot(justified_block_root, justified_slot)
        .ok_or_else(|| {
            Error::MigrationError(format!(
                "Missing state root for justified slot {justified_slot} with latest_block_root \
                 {justified_block_root:?}"
            ))
        })?;

    let unrealized_justified_checkpoint = persisted_fork_choice_v17
        .fork_choice_store_v17
        .unrealized_justified_checkpoint;
    let unrealized_justified_block_root = unrealized_justified_checkpoint.root;
    let unrealized_justified_slot = unrealized_justified_checkpoint
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    let unrealized_justified_state_root = state_summaries_dag
        .state_root_at_slot(unrealized_justified_block_root, unrealized_justified_slot)
        .ok_or_else(|| {
            Error::MigrationError(format!(
                "Missing state root for unrealized justified slot {unrealized_justified_slot} \
                 with latest_block_root {unrealized_justified_block_root:?}"
            ))
        })?;

    let fc_store = BeaconForkChoiceStore::from_persisted_v17(
        persisted_fork_choice_v17.fork_choice_store_v17,
        justified_state_root,
        unrealized_justified_state_root,
        db.clone(),
    )
    .map_err(|e| {
        Error::MigrationError(format!(
            "Error loading fork choice store from persisted: {e:?}"
        ))
    })?;

    info!(
        ?justified_state_root,
        %justified_slot,
        "Added justified state root to fork choice"
    );

    // Construct top-level ForkChoice struct using the patched fork choice store, and the converted
    // proto array.
    let reset_payload_statuses = ResetPayloadStatuses::OnlyWithInvalidPayload;
    let fork_choice = ForkChoice::from_persisted(
        persisted_fork_choice_v17.fork_choice_v17.try_into()?,
        reset_payload_statuses,
        fc_store,
        db.get_chain_spec(),
    )
    .map_err(|e| Error::MigrationError(format!("Unable to build ForkChoice: {e:?}")))?;

    let ops = vec![BeaconChain::<T>::persist_fork_choice_in_batch_standalone(
        &fork_choice,
        db.get_config(),
    )?];

    info!("Upgraded fork choice for DB schema v28");

    Ok(ops)
}

pub fn downgrade_from_v28<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let reset_payload_statuses = ResetPayloadStatuses::OnlyWithInvalidPayload;
    let Some(fork_choice) =
        BeaconChain::<T>::load_fork_choice(db.clone(), reset_payload_statuses, db.get_chain_spec())
            .map_err(|e| Error::MigrationError(format!("Unable to load fork choice: {e:?}")))?
    else {
        warn!("No fork choice to downgrade");
        return Ok(vec![]);
    };

    // Recreate V28 persisted fork choice, then convert each field back to its V17 version.
    let persisted_fork_choice = PersistedForkChoiceV28 {
        fork_choice: fork_choice.to_persisted(),
        fork_choice_store: fork_choice.fc_store().to_persisted(),
    };

    let justified_balances = fork_choice.fc_store().justified_balances();

    // 1. Create `proto_array::PersistedForkChoiceV17`.
    let fork_choice_v17: fork_choice::PersistedForkChoiceV17 = (
        persisted_fork_choice.fork_choice,
        justified_balances.clone(),
    )
        .into();

    let fork_choice_store_v17: PersistedForkChoiceStoreV17 = (
        persisted_fork_choice.fork_choice_store,
        justified_balances.clone(),
    )
        .into();

    let persisted_fork_choice_v17 = PersistedForkChoiceV17 {
        fork_choice_v17,
        fork_choice_store_v17,
    };

    let ops = vec![persisted_fork_choice_v17.as_kv_store_op(FORK_CHOICE_DB_KEY)];

    info!("Downgraded fork choice for DB schema v28");

    Ok(ops)
}
