use crate::{
    beacon_chain::FORK_CHOICE_DB_KEY,
    persisted_fork_choice::PersistedForkChoiceV17,
    summaries_dag::{DAGStateSummary, StateSummariesDAG},
    BeaconChain, BeaconChainTypes, BeaconForkChoiceStore,
};
use fork_choice::{ForkChoice, ForkChoiceStore, ResetPayloadStatuses};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp};
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

    let mut fc_store = BeaconForkChoiceStore::from_persisted_v17(
        persisted_fork_choice_v17.fork_choice_store_v17,
        db.clone(),
    )
    .map_err(|e| {
        Error::MigrationError(format!(
            "Error loading fork choise store from persisted: {e:?}"
        ))
    })?;

    // Fix the justified state roots.
    let justified_block_root = fc_store.justified_checkpoint().root;
    let justified_slot = fc_store
        .justified_checkpoint()
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

    let unrealized_justified_block_root = fc_store.unrealized_justified_checkpoint().root;
    let unrealized_justified_slot = fc_store
        .unrealized_justified_checkpoint()
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

    info!(
        ?justified_state_root,
        %justified_slot,
        "Writing fork choice justified state root"
    );
    fc_store
        .set_justified_checkpoint(*fc_store.justified_checkpoint(), justified_state_root)
        .map_err(|e| {
            Error::MigrationError(format!("Unable to set justified state checkpoint: {e:?}"))
        })?;

    info!(
        ?unrealized_justified_state_root,
        %unrealized_justified_slot,
        "Writing fork choice unrealized justified state root"
    );
    fc_store.set_unrealized_justified_checkpoint(
        *fc_store.unrealized_justified_checkpoint(),
        unrealized_justified_state_root,
    );

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
    )?];

    Ok(ops)
}

pub fn downgrade_from_v28<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // FIXME(sproul): TODO
    Ok(vec![])
}
