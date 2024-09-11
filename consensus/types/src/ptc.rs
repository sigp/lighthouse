use crate::*;
use safe_arith::SafeArith;

/// TODO(EIP-7732): is it easier to return u64 or usize?
#[derive(Clone, Debug, PartialEq)]
pub struct PTC<E: EthSpec>(FixedVector<usize, E::PTCSize>);

impl<E: EthSpec> PTC<E> {
    pub fn from_committees(committees: &[BeaconCommittee]) -> Result<Self, BeaconStateError> {
        // this function is only used here and
        // I have no idea where else to put it
        fn bit_floor(n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                1 << (n.leading_zeros() as u64 ^ 63)
            }
        }

        let committee_count_per_slot = committees.len() as u64;
        let committees_per_slot = bit_floor(std::cmp::min(
            committee_count_per_slot,
            E::PTCSize::to_u64(),
        )) as usize;
        let members_per_committee = E::PTCSize::to_usize().safe_div(committees_per_slot)?;

        let mut ptc = Vec::with_capacity(E::PTCSize::to_usize());
        for idx in 0..committees_per_slot {
            let beacon_committee = committees
                .get(idx as usize)
                .ok_or_else(|| Error::InvalidCommitteeIndex(idx as u64))?;
            ptc.extend_from_slice(&beacon_committee.committee[..members_per_committee]);
        }

        Ok(Self(FixedVector::from(ptc)))
    }
}

impl<'a, E: EthSpec> IntoIterator for &'a PTC<E> {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<E: EthSpec> IntoIterator for PTC<E> {
    type Item = usize;
    type IntoIter = std::vec::IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
