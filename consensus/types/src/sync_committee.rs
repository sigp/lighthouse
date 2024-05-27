use crate::test_utils::TestRandom;
use crate::{EthSpec, FixedVector, SyncSubnetId};
use bls::PublicKeyBytes;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq)]
pub enum Error {
    ArithError(ArithError),
    InvalidSubcommitteeRange {
        start_subcommittee_index: usize,
        end_subcommittee_index: usize,
        subcommittee_index: usize,
    },
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Error {
        Error::ArithError(e)
    }
}

#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
pub struct SyncCommittee<E: EthSpec> {
    pub pubkeys: FixedVector<PublicKeyBytes, E::SyncCommitteeSize>,
    pub aggregate_pubkey: PublicKeyBytes,
}

impl<E: EthSpec> SyncCommittee<E> {
    /// Create a temporary sync committee that should *never* be included in a legitimate consensus object.
    pub fn temporary() -> Self {
        Self {
            pubkeys: FixedVector::from_elem(PublicKeyBytes::empty()),
            aggregate_pubkey: PublicKeyBytes::empty(),
        }
    }

    /// Return the pubkeys in this `SyncCommittee` for the given `subcommittee_index`.
    pub fn get_subcommittee_pubkeys(
        &self,
        subcommittee_index: usize,
    ) -> Result<Vec<PublicKeyBytes>, Error> {
        let start_subcommittee_index = subcommittee_index.safe_mul(E::sync_subcommittee_size())?;
        let end_subcommittee_index =
            start_subcommittee_index.safe_add(E::sync_subcommittee_size())?;
        self.pubkeys
            .get(start_subcommittee_index..end_subcommittee_index)
            .ok_or(Error::InvalidSubcommitteeRange {
                start_subcommittee_index,
                end_subcommittee_index,
                subcommittee_index,
            })
            .map(|s| s.to_vec())
    }

    /// For a given `pubkey`, finds all subcommittees that it is included in, and maps the
    /// subcommittee index (typed as `SyncSubnetId`) to all positions this `pubkey` is associated
    /// with within the subcommittee.
    pub fn subcommittee_positions_for_public_key(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<HashMap<SyncSubnetId, Vec<usize>>, Error> {
        let mut subnet_positions = HashMap::new();
        for (committee_index, validator_pubkey) in self.pubkeys.iter().enumerate() {
            if pubkey == validator_pubkey {
                let subcommittee_index = committee_index.safe_div(E::sync_subcommittee_size())?;
                let position_in_subcommittee =
                    committee_index.safe_rem(E::sync_subcommittee_size())?;
                subnet_positions
                    .entry(SyncSubnetId::new(subcommittee_index as u64))
                    .or_insert_with(Vec::new)
                    .push(position_in_subcommittee);
            }
        }
        Ok(subnet_positions)
    }

    /// Returns `true` if the pubkey exists in the `SyncCommittee`.
    pub fn contains(&self, pubkey: &PublicKeyBytes) -> bool {
        self.pubkeys.contains(pubkey)
    }
}
