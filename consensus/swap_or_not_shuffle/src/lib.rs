//! Provides list-shuffling functions matching the Ethereum 2.0 specification.
//!
//! See
//! [compute_shuffled_index](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#compute_shuffled_index)
//! for specifications.
//!
//! There are two functions exported by this crate:
//!
//! - `compute_shuffled_index`: given a single index, computes the index resulting from a shuffle.
//! Runs in less time than it takes to run `shuffle_list`.
//! - `shuffle_list`: shuffles an entire list in-place. Runs in less time than it takes to run
//! `compute_shuffled_index` on each index.
//!
//! In general, use `compute_shuffled_index` to calculate the shuffling of a small subset of a much
//! larger list (~250x larger is a good guide, but solid figures yet to be calculated).

mod compute_shuffled_index;
mod shuffle_list;

pub use compute_shuffled_index::compute_shuffled_index;
pub use shuffle_list::shuffle_list;

type Hash256 = ethereum_types::H256;
