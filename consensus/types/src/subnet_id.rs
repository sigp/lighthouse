//! Identifies each shard by an integer identifier.
use crate::{AttestationData, ChainSpec, CommitteeIndex, Epoch, EthSpec, Slot};
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

    #[allow(clippy::integer_arithmetic)]
    /// Computes the set of subnets the node should be subscribed to during the current epoch,
    /// along with the first epoch in which these subscriptions are no longer valid.
    pub fn compute_subnets_for_epoch<T: EthSpec>(
        node_id: ethereum_types::U256,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<(impl Iterator<Item = SubnetId>, Epoch), &'static str> {
        let node_id_prefix =
            (node_id >> (256 - spec.attestation_subnet_prefix_bits() as usize)).as_usize();

        let subscription_event_idx = epoch.as_u64() / spec.epochs_per_subnet_subscription;
        let permutation_seed =
            eth2_hashing::hash(&int_to_bytes::int_to_bytes8(subscription_event_idx));

        let num_subnets = 1 << spec.attestation_subnet_prefix_bits();

        let permutated_prefix = compute_shuffled_index(
            node_id_prefix,
            num_subnets,
            &permutation_seed,
            spec.shuffle_round_count,
        )
        .ok_or("Unable to shuffle")? as u64;

        // Get the constants we need to avoid holding a reference to the spec
        let &ChainSpec {
            subnets_per_node,
            attestation_subnet_count,
            ..
        } = spec;

        let subnet_set_generator = (0..subnets_per_node).map(move |idx| {
            SubnetId::new((permutated_prefix + idx as u64) % attestation_subnet_count)
        });
        let valid_until_epoch = (subscription_event_idx + 1) * spec.epochs_per_subnet_subscription;
        Ok((subnet_set_generator, valid_until_epoch.into()))
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
