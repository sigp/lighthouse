use crate::per_block_processing::{compute_time_at_slot, is_transition_completed};
use safe_arith::ArithError;
use types::{BeaconState, ChainSpec, EthSpec, Hash256};

#[derive(Debug)]
pub enum Error<E> {
    ArithError(ArithError),
    GetPowChainHead(E),
}

pub struct AssembleBlockParams {
    pub parent_hash: Hash256,
    pub timestamp: u64,
}

fn is_valid_transition_block(_pow_block: Hash256) -> bool {
    true
}

pub fn get_execution_payload<E, F, T>(
    state: &BeaconState<T>,
    get_pow_chain_head: F,
    spec: &ChainSpec,
) -> Result<Option<AssembleBlockParams>, Error<E>>
where
    T: EthSpec,
    F: Fn() -> Result<Hash256, E>,
{
    let transition_completed = is_transition_completed(state);

    if !transition_completed {
        let pow_chain_head = get_pow_chain_head().map_err(Error::GetPowChainHead)?;
        if !is_valid_transition_block(pow_chain_head) {
            Ok(None)
        } else {
            let timestamp = compute_time_at_slot(state, spec).map_err(Error::ArithError)?;
            Ok(Some(AssembleBlockParams {
                parent_hash: pow_chain_head,
                timestamp,
            }))
        }
    } else {
        let timestamp = compute_time_at_slot(state, spec).map_err(Error::ArithError)?;
        let parent_hash = state.latest_execution_payload_header.block_hash;

        Ok(Some(AssembleBlockParams {
            parent_hash,
            timestamp,
        }))
    }
}
