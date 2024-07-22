//! Identifies each shard by an integer identifier.
use crate::{AttestationRef, ChainSpec, CommitteeIndex, Epoch, EthSpec, Slot};
use lazy_static::lazy_static;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
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

    /// Computes the set of subnets the node should be subscribed to during the current epoch,
    /// along with the first epoch in which these subscriptions are no longer valid.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn compute_subnets_for_epoch<E: EthSpec>(
        node_id: ethereum_types::U256,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<(impl Iterator<Item = SubnetId>, Epoch), &'static str> {
        // simplify variable naming
        let subscription_duration = spec.epochs_per_subnet_subscription;
        let prefix_bits = spec.attestation_subnet_prefix_bits as u64;
        let shuffling_prefix_bits = spec.attestation_subnet_shuffling_prefix_bits as u64;

        // calculate the prefixes used to compute the subnet and shuffling
        let node_id_prefix = (node_id >> (256 - prefix_bits)).as_u64();
        let shuffling_prefix = (node_id >> (256 - (prefix_bits + shuffling_prefix_bits))).as_u64();

        // number of groups the shuffling creates
        let shuffling_groups = 1 << shuffling_prefix_bits;
        // shuffling group for this node
        let shuffling_bits = shuffling_prefix % shuffling_groups;
        let epoch_transition = (node_id_prefix
            + (shuffling_bits * (subscription_duration >> shuffling_prefix_bits)))
            % subscription_duration;

        // Calculate at which epoch this node needs to re-evaluate
        let valid_until_epoch = epoch.as_u64()
            + subscription_duration
                .saturating_sub((epoch.as_u64() + epoch_transition) % subscription_duration);

        let subscription_event_idx = (epoch.as_u64() + epoch_transition) / subscription_duration;
        let permutation_seed =
            ethereum_hashing::hash(&int_to_bytes::int_to_bytes8(subscription_event_idx));

        let num_subnets = 1 << spec.attestation_subnet_prefix_bits;
        let permutated_prefix = compute_shuffled_index(
            node_id_prefix as usize,
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
    use super::*;

    /// A set of tests compared to the python specification
    #[test]
    fn compute_subnets_for_epoch_unit_test() {
        // Randomized variables used generated with the python specification
        let node_ids = [
            "0",
            "88752428858350697756262172400162263450541348766581994718383409852729519486397",
            "18732750322395381632951253735273868184515463718109267674920115648614659369468",
            "27726842142488109545414954493849224833670205008410190955613662332153332462900",
            "39755236029158558527862903296867805548949739810920318269566095185775868999998",
            "31899136003441886988955119620035330314647133604576220223892254902004850516297",
            "58579998103852084482416614330746509727562027284701078483890722833654510444626",
            "28248042035542126088870192155378394518950310811868093527036637864276176517397",
            "60930578857433095740782970114409273483106482059893286066493409689627770333527",
            "103822458477361691467064888613019442068586830412598673713899771287914656699997",
        ]
        .map(|v| ethereum_types::U256::from_dec_str(v).unwrap());

        let epochs = [
            54321u64, 1017090249, 1827566880, 846255942, 766597383, 1204990115, 1616209495,
            1774367616, 1484598751, 3525502229,
        ]
        .map(Epoch::from);

        // Test mainnet
        let spec = ChainSpec::mainnet();

        // Calculated by hand
        let expected_valid_time = [
            54528u64, 1017090255, 1827567030, 846256049, 766597387, 1204990287, 1616209536,
            1774367857, 1484598847, 3525502311,
        ];

        // Calculated from pyspec
        let expected_subnets = [
            vec![4u64, 5u64],
            vec![31, 32],
            vec![39, 40],
            vec![38, 39],
            vec![53, 54],
            vec![57, 58],
            vec![48, 49],
            vec![1, 2],
            vec![34, 35],
            vec![37, 38],
        ];

        for x in 0..node_ids.len() {
            println!("Test: {}", x);
            println!(
                "NodeId: {}\n Epoch: {}\n, expected_update_time: {}\n, expected_subnets: {:?}",
                node_ids[x], epochs[x], expected_valid_time[x], expected_subnets[x]
            );

            let (computed_subnets, valid_time) = SubnetId::compute_subnets_for_epoch::<
                crate::MainnetEthSpec,
            >(node_ids[x], epochs[x], &spec)
            .unwrap();

            assert_eq!(
                expected_subnets[x],
                computed_subnets.map(SubnetId::into).collect::<Vec<u64>>()
            );
            assert_eq!(Epoch::from(expected_valid_time[x]), valid_time);
        }
    }
}
