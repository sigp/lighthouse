use crate::beacon_fork_choice_store::{PersistedForkChoiceStoreV10, PersistedForkChoiceStoreV11};
use crate::persisted_fork_choice::{PersistedForkChoiceV10, PersistedForkChoiceV11};
use slog::{warn, Logger};
use std::collections::BTreeSet;

/// Add the equivocating indices field.
pub fn update_fork_choice(fork_choice_v10: PersistedForkChoiceV10) -> PersistedForkChoiceV11 {
    let PersistedForkChoiceStoreV10 {
        balances_cache,
        time,
        finalized_checkpoint,
        justified_checkpoint,
        justified_balances,
        best_justified_checkpoint,
        unrealized_justified_checkpoint,
        unrealized_finalized_checkpoint,
        proposer_boost_root,
    } = fork_choice_v10.fork_choice_store;

    PersistedForkChoiceV11 {
        fork_choice: fork_choice_v10.fork_choice,
        fork_choice_store: PersistedForkChoiceStoreV11 {
            balances_cache,
            time,
            finalized_checkpoint,
            justified_checkpoint,
            justified_balances,
            best_justified_checkpoint,
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
            proposer_boost_root,
            equivocating_indices: BTreeSet::new(),
        },
    }
}

pub fn downgrade_fork_choice(
    fork_choice_v11: PersistedForkChoiceV11,
    log: Logger,
) -> PersistedForkChoiceV10 {
    let PersistedForkChoiceStoreV11 {
        balances_cache,
        time,
        finalized_checkpoint,
        justified_checkpoint,
        justified_balances,
        best_justified_checkpoint,
        unrealized_justified_checkpoint,
        unrealized_finalized_checkpoint,
        proposer_boost_root,
        equivocating_indices,
    } = fork_choice_v11.fork_choice_store;

    if !equivocating_indices.is_empty() {
        warn!(
            log,
            "Deleting slashed validators from fork choice store";
            "count" => equivocating_indices.len(),
            "message" => "this may make your node more susceptible to following the wrong chain",
        );
    }

    PersistedForkChoiceV10 {
        fork_choice: fork_choice_v11.fork_choice,
        fork_choice_store: PersistedForkChoiceStoreV10 {
            balances_cache,
            time,
            finalized_checkpoint,
            justified_checkpoint,
            justified_balances,
            best_justified_checkpoint,
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
            proposer_boost_root,
        },
    }
}
