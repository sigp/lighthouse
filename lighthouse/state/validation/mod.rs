use std::collections::HashMap;
use super::block;
use super::bls;
use super::Logger;
use super::db;
use super::attestation_record;
use super::ssz;
use super::transition::attestation_parent_hashes;
use super::utils;

mod attestation;
mod ssz_block;

type Slot = u64;
type ShardId = u64;
type AttesterMap = HashMap<(Slot, ShardId), Vec<usize>>;
type ProposerMap = HashMap<Slot, usize>;
