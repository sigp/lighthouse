//! Provides list-shuffling functions matching the Ethereum 2.0 specification.
//!
//! See
//! [get_permutated_index](https://github.com/ethereum/eth2.0-specs/blob/0.4.0/specs/core/0_beacon-chain.md#get_permuted_index)
//! for specifications.
//!
//! There are two functions exported by this crate:
//!
//! - `get_permutated_index`: given a single index, computes the index resulting from a shuffle.
//! Runs in less time than it takes to run `shuffle_list`.
//! - `shuffle_list`: shuffles an entire list in-place. Runs in less time than it takes to run
//! `get_permutated_index` on each index.
//!
//! In general, use `get_permutated_list` to calculate the shuffling of a small subset of a much
//! larger list (~250x larger is a good guide, but solid figures yet to be calculated).

mod get_permutated_index;
mod shuffle_list;

pub use get_permutated_index::get_permutated_index;
pub use shuffle_list::shuffle_list;
