//! Identifies each shard by an integer identifier.
use crate::{AttestationData, ChainSpec, CommitteeIndex, Epoch, EthSpec, Slot};
use eth2_hashing::hash;
use ethereum_types::U256;
use int_to_bytes::int_to_bytes32;
use safe_arith::{ArithError, SafeArith};
use serde_derive::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use swap_or_not_shuffle::compute_shuffled_index;

const MAX_SUBNET_ID: usize = 64;

lazy_static! {
    static ref SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(MAX_SUBNET_ID);

        for i in 0..MAX_SUBNET_ID {
            v.push(i.to_string());
        }
        v
    };
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubnetId(#[serde(with = "eth2_serde_utils::quoted_u64")] u64);

pub fn subnet_id_to_string(i: u64) -> &'static str {
    if i < MAX_SUBNET_ID as u64 {
        SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below MAX_SUBNET_ID")
    } else {
        "subnet id out of range"
    }
}

impl SubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    /// Compute the subnet for an attestation with `attestation_data` where each slot in the
    /// attestation epoch contains `committee_count_per_slot` committees.
    pub fn compute_subnet_for_attestation_data<T: EthSpec>(
        attestation_data: &AttestationData,
        committee_count_per_slot: u64,
        spec: &ChainSpec,
    ) -> Result<SubnetId, ArithError> {
        Self::compute_subnet::<T>(
            attestation_data.slot,
            attestation_data.index,
            committee_count_per_slot,
            spec,
        )
    }

    /// Compute the subnet for an attestation with `attestation.data.slot == slot` and
    /// `attestation.data.index == committee_index` where each slot in the attestation epoch
    /// contains `committee_count_at_slot` committees.
    pub fn compute_subnet<T: EthSpec>(
        slot: Slot,
        committee_index: CommitteeIndex,
        committee_count_at_slot: u64,
        spec: &ChainSpec,
    ) -> Result<SubnetId, ArithError> {
        let slots_since_epoch_start: u64 = slot.as_u64().safe_rem(T::slots_per_epoch())?;

        let committees_since_epoch_start =
            committee_count_at_slot.safe_mul(slots_since_epoch_start)?;

        Ok(committees_since_epoch_start
            .safe_add(committee_index)?
            .safe_rem(spec.attestation_subnet_count)?
            .into())
    }

    pub fn compute_subnets_for_epoch<T: EthSpec>(
        node_id: U256,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Vec<SubnetId> {
        const ATTESTATION_SUBNET_EXTRA_BITS: usize = 6;
        const SUBNETS_PER_NODE: usize = 2;
        const ATTESTATION_SUBNET_PREFIX_BITS: usize = 7;
        const SUBNET_DURATION_IN_EPOCHS: u64 = 30;
        // ceil(log2(SUBNETS_PER_NODE)) + ATTESTATION_SUBNET_EXTRA_BITS;

        // ATTESTATION_SUBNET_EXTRA_BITS needs to be <= usize::BITS;
        let node_id_prefix = (node_id >> (256 - ATTESTATION_SUBNET_EXTRA_BITS)).as_usize();
        let permutation_seed = eth2_hashing::hash(&int_to_bytes::int_to_bytes8(
            epoch.as_u64() / SUBNET_DURATION_IN_EPOCHS,
        ));
        let num_subnets = 1 << ATTESTATION_SUBNET_PREFIX_BITS;

        let permutated_prefix = compute_shuffled_index(
            node_id_prefix,
            num_subnets,
            &permutation_seed,
            spec.shuffle_round_count,
        )
        .expect("Every shuffling condition is met ¿?") as u64;
        (0..SUBNETS_PER_NODE)
            .map(|idx| {
                SubnetId::new((permutated_prefix + idx as u64) % spec.attestation_subnet_count)
            })
            .collect()
    }
}

impl Deref for SubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for SubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<u64> for SubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &SubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for SubnetId {
    fn as_ref(&self) -> &str {
        subnet_id_to_string(self.0)
    }
}
