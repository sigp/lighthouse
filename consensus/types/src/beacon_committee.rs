use crate::*;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct BeaconCommittee<'a> {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: &'a [usize],
}

impl<'a> BeaconCommittee<'a> {
    pub fn into_owned(self) -> OwnedBeaconCommittee {
        OwnedBeaconCommittee {
            slot: self.slot,
            index: self.index,
            committee: self.committee.to_vec(),
        }
    }
}

#[derive(arbitrary::Arbitrary, Default, Clone, Debug, PartialEq)]
pub struct OwnedBeaconCommittee {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: Vec<usize>,
}
