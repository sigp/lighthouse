use crate::{BlockId, StateId};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::ssz_proof::{SszProofQuery, SszProofResponse};
use types::SszProofError;
use warp::Rejection;

fn proof_error(error: SszProofError) -> Rejection {
    match error {
        SszProofError::State(_) | SszProofError::List(_) | SszProofError::InvalidTree => {
            warp_utils::reject::custom_server_error(error.to_string())
        }
        _ => warp_utils::reject::custom_bad_request(error.to_string()),
    }
}

fn validate_query(query: &SszProofQuery) -> Result<(), Rejection> {
    if query.gindex == 0 {
        return Err(proof_error(SszProofError::InvalidGeneralizedIndex(0)));
    }
    Ok(())
}

pub fn state_proof<T: BeaconChainTypes>(
    state_id: StateId,
    query: SszProofQuery,
    chain: &BeaconChain<T>,
) -> Result<SszProofResponse, Rejection> {
    validate_query(&query)?;
    let (mut state, execution_optimistic, finalized) = state_id.state(chain)?;
    let version = state.fork_name_unchecked();
    let data = state.get_ssz_proof(query.gindex).map_err(proof_error)?;
    Ok(SszProofResponse {
        version,
        execution_optimistic,
        finalized,
        data,
    })
}

pub fn block_proof<T: BeaconChainTypes>(
    block_id: BlockId,
    query: SszProofQuery,
    chain: &BeaconChain<T>,
) -> Result<SszProofResponse, Rejection> {
    validate_query(&query)?;
    // The header is enough to build these proofs without fetching a payload from the execution client.
    let (block, execution_optimistic, finalized) = block_id.blinded_block(chain)?;
    let version = chain.spec.fork_name_at_slot::<T::EthSpec>(block.slot());
    let data = block
        .signed_block_header()
        .message
        .get_ssz_proof(query.gindex)
        .map_err(proof_error)?;
    Ok(SszProofResponse {
        version,
        execution_optimistic,
        finalized,
        data,
    })
}
