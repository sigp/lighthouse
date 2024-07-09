//! Garbage collection process that runs at start-up to clean up the database.
use crate::hot_cold_store::HotColdDB;
use crate::{Error, LevelDB, StoreOp};
use slog::debug;
use types::EthSpec;

impl<E> HotColdDB<E, LevelDB<E>, LevelDB<E>>
where
    E: EthSpec,
{
    /// Clean up the database by performing one-off maintenance at start-up.
    pub fn remove_garbage(&self) -> Result<(), Error> {
        self.delete_temp_states()?;
        Ok(())
    }

    /// Delete the temporary states that were leftover by failed block imports.
    pub fn delete_temp_states(&self) -> Result<(), Error> {
        let delete_ops =
            self.iter_temporary_state_roots()
                .try_fold(vec![], |mut ops, state_root| {
                    let state_root = state_root?;
                    ops.push(StoreOp::DeleteState(state_root, None));
                    ops.push(StoreOp::DeleteStateTemporaryFlag(state_root));
                    Result::<_, Error>::Ok(ops)
                })?;

        if !delete_ops.is_empty() {
            debug!(
                self.log,
                "Garbage collecting {} temporary states",
                delete_ops.len() / 2
            );
            self.do_atomically_with_block_and_blobs_cache(delete_ops)?;
        }

        Ok(())
    }
}
