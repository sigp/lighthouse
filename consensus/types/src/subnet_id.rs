//! Identifies each shard by an integer identifier.
use crate::{AttestationRef, ChainSpec, CommitteeIndex, EthSpec, Slot};
use alloy_primitives::{bytes::Buf, U256};
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;

const MAX_SUBNET_ID: usize = 64;

/// The number of bits in a Discovery `NodeId`. This is used for binary operations on the node-id
/// data.
const NODE_ID_BITS: u64 = 256;

static SUBNET_ID_TO_STRING: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut v = Vec::with_capacity(MAX_SUBNET_ID);

    for i in 0..MAX_SUBNET_ID {
        v.push(i.to_string());
    }
    v
});

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

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

    /// Compute the subnet for an attestation where each slot in the
    /// attestation epoch contains `committee_count_per_slot` committees.
    pub fn compute_subnet_for_attestation<E: EthSpec>(
        attestation: AttestationRef<E>,
        committee_count_per_slot: u64,
        spec: &ChainSpec,
    ) -> Result<SubnetId, ArithError> {
        let committee_index = attestation.committee_index().ok_or(ArithError::Overflow)?;

        Self::compute_subnet::<E>(
            attestation.data().slot,
            committee_index,
            committee_count_per_slot,
            spec,
        )
    }

    /// Compute the subnet for an attestation with `attestation.data.slot == slot` and
    /// `attestation.data.index == committee_index` where each slot in the attestation epoch
    /// contains `committee_count_at_slot` committees.
    pub fn compute_subnet<E: EthSpec>(
        slot: Slot,
        committee_index: CommitteeIndex,
        committee_count_at_slot: u64,
        spec: &ChainSpec,
    ) -> Result<SubnetId, ArithError> {
        let slots_since_epoch_start: u64 = slot.as_u64().safe_rem(E::slots_per_epoch())?;

        let committees_since_epoch_start =
            committee_count_at_slot.safe_mul(slots_since_epoch_start)?;

        Ok(committees_since_epoch_start
            .safe_add(committee_index)?
            .safe_rem(spec.attestation_subnet_count)?
            .into())
    }

    /// Computes the set of subnets the node should be subscribed to. We subscribe to these subnets
    /// for the duration of the node's runtime.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn compute_attestation_subnets(
        raw_node_id: [u8; 32],
        spec: &ChainSpec,
    ) -> impl Iterator<Item = SubnetId> {
        // The bits of the node-id we are using to define the subnets.
        let prefix_bits = spec.attestation_subnet_prefix_bits as u64;

        let node_id = U256::from_be_slice(&raw_node_id);
        // calculate the prefixes used to compute the subnet and shuffling
        let node_id_prefix = (node_id >> (NODE_ID_BITS - prefix_bits))
            .as_le_slice()
            .get_u64_le();

        // Get the constants we need to avoid holding a reference to the spec
        let &ChainSpec {
            subnets_per_node,
            attestation_subnet_count,
            ..
        } = spec;

        (0..subnets_per_node)
            .map(move |idx| SubnetId::new((node_id_prefix + idx as u64) % attestation_subnet_count))
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

impl From<SubnetId> for u64 {
    fn from(from: SubnetId) -> u64 {
        from.0
    }
}

impl From<&SubnetId> for u64 {
    fn from(from: &SubnetId) -> u64 {
        from.0
    }
}

impl AsRef<str> for SubnetId {
    fn as_ref(&self) -> &str {
        subnet_id_to_string(self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::Uint256;

    use super::*;

    /// A set of tests compared to the python specification
    #[test]
    fn compute_attestation_subnets_test() {
        // Randomized variables used generated with the python specification
        let node_ids = [
            "0",
            "88752428858350697756262172400162263450541348766581994718383409852729519486397",
            "18732750322395381632951253735273868184515463718109267674920115648614659369468",
            "27726842142488109545414954493849224833670205008410190955613662332153332462900",
            "39755236029158558527862903296867805548949739810920318269566095185775868999998",
            "31899136003441886988955119620035330314647133604576220223892254902004850516297",
        ]
        .map(|v| Uint256::from_str_radix(v, 10).unwrap().to_be_bytes::<32>());

        let expected_subnets = [
            vec![0, 1],
            vec![49u64, 50u64],
            vec![10, 11],
            vec![15, 16],
            vec![21, 22],
            vec![17, 18],
        ];

        // Test mainnet
        let spec = ChainSpec::mainnet();

        for x in 0..node_ids.len() {
            println!("Test: {}", x);
            println!(
                "NodeId: {:?}\nExpected_subnets: {:?}",
                node_ids[x], expected_subnets[x]
            );

            let computed_subnets = SubnetId::compute_attestation_subnets(node_ids[x], &spec);

            assert_eq!(
                expected_subnets[x],
                computed_subnets.map(SubnetId::into).collect::<Vec<u64>>()
            );
        }
    }
}
