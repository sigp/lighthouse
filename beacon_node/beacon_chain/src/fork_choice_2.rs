use proto_array_fork_choice::{core::ProtoArray, ProtoArrayForkChoice};
use std::marker::PhantomData;
use types::Hash256;

pub struct ForkChoice<T> {
    /// The underlying representation of the block DAG.
    proto_array: ProtoArrayForkChoice,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    _phantom: PhantomData<T>,
}
