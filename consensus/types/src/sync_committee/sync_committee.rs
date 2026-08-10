use std::collections::HashMap;

use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash_derive::TreeHash;

use crate::{core::Spec, fork::ForkName, sync_committee::SyncSubnetId};

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

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SyncCommittee {
    pub pubkeys: FixedVector<PublicKeyBytes, typenum::U<{ Spec::SYNC_COMMITTEE_SIZE }>>,
    pub aggregate_pubkey: PublicKeyBytes,
}

impl SyncCommittee {
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
        let start_subcommittee_index = subcommittee_index.safe_mul(Spec::SYNC_SUBCOMMITTEE_SIZE)?;
        let end_subcommittee_index =
            start_subcommittee_index.safe_add(Spec::SYNC_SUBCOMMITTEE_SIZE)?;
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
                let subcommittee_index = committee_index.safe_div(Spec::SYNC_SUBCOMMITTEE_SIZE)?;
                let position_in_subcommittee =
                    committee_index.safe_rem(Spec::SYNC_SUBCOMMITTEE_SIZE)?;
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
