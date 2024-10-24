use super::{
    map_beacon_state_altair_tree_list_fields_immutable,
    map_beacon_state_base_tree_list_fields_immutable,
    map_beacon_state_bellatrix_tree_list_fields_immutable,
    map_beacon_state_capella_tree_list_fields_immutable,
    map_beacon_state_deneb_tree_list_fields_immutable,
    map_beacon_state_electra_tree_list_fields_immutable,
};
use crate::{historical_summary::HistoricalSummary, *};
use milhouse::{mem::MemorySize, List, Vector};

impl<E: EthSpec> MemorySize for BeaconState<E> {
    fn self_pointer(&self) -> usize {
        self as *const _ as usize
    }

    fn subtrees<'a>(&'a self) -> Vec<&'a (dyn MemorySize + 'a)> {
        let mut subtrees: Vec<&'a (dyn MemorySize + 'a)> = vec![];
        match self {
            Self::Base(self_inner) => {
                map_beacon_state_base_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
            Self::Altair(self_inner) => {
                map_beacon_state_altair_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
            Self::Bellatrix(self_inner) => {
                map_beacon_state_bellatrix_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
            Self::Capella(self_inner) => {
                map_beacon_state_capella_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
            Self::Deneb(self_inner) => {
                map_beacon_state_deneb_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
            Self::Electra(self_inner) => {
                map_beacon_state_electra_tree_list_fields_immutable!(
                    &'a _,
                    self_inner,
                    |_, self_field| {
                        subtrees.push(self_field);
                    }
                );
            }
        }

        if let Ok(current_sc) = self.current_sync_committee() {
            subtrees.push(&**current_sc);
        }
        if let Ok(next_sc) = self.next_sync_committee() {
            subtrees.push(&**next_sc);
        }

        for committee_cache in self.committee_caches() {
            subtrees.push(&**committee_cache);
        }

        // FIXME(sproul): more caches

        subtrees
    }

    fn intrinsic_size(&self) -> usize {
        // This is a close-enough approximation for now.
        std::mem::size_of::<Self>()
    }
}

impl<E: EthSpec> MemorySize for SyncCommittee<E> {
    fn self_pointer(&self) -> usize {
        self as *const _ as usize
    }

    fn subtrees(&self) -> Vec<&dyn MemorySize> {
        vec![]
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn intrinsic_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.pubkeys.len() * std::mem::size_of::<PublicKeyBytes>()
    }
}
