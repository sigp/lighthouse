use itertools::Itertools;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, btree_map::Entry},
};
use store::HotStateSummary;
use types::{Hash256, Slot};

#[derive(Debug, Clone, Copy)]
pub struct DAGStateSummary {
    pub slot: Slot,
    pub latest_block_root: Hash256,
    pub latest_block_slot: Slot,
    pub previous_state_root: Hash256,
}

pub struct StateSummariesDAG {
    // state_root -> state_summary
    state_summaries_by_state_root: HashMap<Hash256, DAGStateSummary>,
    // (block_root, payload_status)-> state slot -> [(state_root, state summary)]
    //
    // Since Gloas there can be up to two `(state_root, state summary)` pairs for each block root
    // and slot: the pending and full states.
    state_summaries_by_block_root:
        HashMap<Hash256, BTreeMap<Slot, Vec<(Hash256, DAGStateSummary)>>>,
    // parent_state_root -> Vec<children_state_root>
    // cached value to prevent having to recompute in each recursive call into `descendants_of`
    child_state_roots: HashMap<Hash256, Vec<Hash256>>,
}

#[derive(Debug)]
pub enum Error {
    ConflictingStateSummary {
        block_root: Hash256,
        existing_state_summaries: Vec<(Slot, Hash256)>,
        new_state_summary: (Slot, Hash256),
    },
    MissingStateSummary(Hash256),
    MissingChildStateRoot(Hash256),
    RequestedSlotAboveSummary {
        starting_state_root: Hash256,
        ancestor_slot: Slot,
        state_root: Hash256,
        state_slot: Slot,
    },
    RootUnknownPreviousStateRoot(Slot, Hash256),
    RootUnknownAncestorStateRoot {
        starting_state_root: Hash256,
        ancestor_slot: Slot,
        root_state_root: Hash256,
        root_state_slot: Slot,
    },
    CircularAncestorChain {
        state_root: Hash256,
        previous_state_root: Hash256,
        slot: Slot,
        last_slot: Slot,
    },
}

impl StateSummariesDAG {
    pub fn new(state_summaries: Vec<(Hash256, DAGStateSummary)>) -> Result<Self, Error> {
        // Group them by latest block root, and sorted state slot
        let mut state_summaries_by_state_root = HashMap::new();
        let mut state_summaries_by_block_root = HashMap::<_, BTreeMap<_, _>>::new();
        let mut child_state_roots = HashMap::<_, Vec<_>>::new();

        for (state_root, summary) in state_summaries.into_iter() {
            let summaries = state_summaries_by_block_root
                .entry(summary.latest_block_root)
                .or_default();

            // Sanity check to ensure no duplicate summaries for the tuple (block_root, state_slot)
            match summaries.entry(summary.slot) {
                Entry::Vacant(entry) => {
                    entry.insert(vec![(state_root, summary)]);
                }
                Entry::Occupied(mut existing) => {
                    let slot_summaries = existing.get_mut();
                    let (existing_state_root, existing_summary) = if let Some(value) =
                        slot_summaries.first()
                        && slot_summaries.len() == 1
                    {
                        value
                    } else {
                        return Err(Error::ConflictingStateSummary {
                            block_root: summary.latest_block_root,
                            existing_state_summaries: slot_summaries
                                .iter()
                                .map(|(state_root, _)| (summary.slot, *state_root))
                                .collect(),
                            new_state_summary: (summary.slot, state_root),
                        });
                    };
                    if existing_summary.previous_state_root == state_root {
                        // New summary is pending, insert before existing.
                        slot_summaries.insert(0, (state_root, summary));
                    } else if summary.previous_state_root == *existing_state_root {
                        // New summary is full, insert after existing.
                        slot_summaries.push((state_root, summary));
                    } else {
                        // TODO(gloas): different error here to distinguish from above
                        return Err(Error::ConflictingStateSummary {
                            block_root: summary.latest_block_root,
                            existing_state_summaries: slot_summaries
                                .iter()
                                .map(|(state_root, _)| (summary.slot, *state_root))
                                .collect(),
                            new_state_summary: (summary.slot, state_root),
                        });
                    }
                }
            }

            state_summaries_by_state_root.insert(state_root, summary);

            child_state_roots
                .entry(summary.previous_state_root)
                .or_default()
                .push(state_root);
            // Add empty entry for the child state
            child_state_roots.entry(state_root).or_default();
        }

        Ok(Self {
            state_summaries_by_state_root,
            state_summaries_by_block_root,
            child_state_roots,
        })
    }

    // Returns all non-unique latest block roots of a given set of states
    pub fn blocks_of_states<'a, I: Iterator<Item = &'a Hash256>>(
        &self,
        state_roots: I,
    ) -> Result<Vec<(Hash256, Slot)>, Error> {
        state_roots
            .map(|state_root| {
                let summary = self
                    .state_summaries_by_state_root
                    .get(state_root)
                    .ok_or(Error::MissingStateSummary(*state_root))?;
                Ok((summary.latest_block_root, summary.latest_block_slot))
            })
            .collect()
    }

    // Returns all unique latest blocks of this DAG's summaries
    pub fn iter_blocks(&self) -> impl Iterator<Item = (Hash256, Slot)> + '_ {
        self.state_summaries_by_state_root
            .values()
            .map(|summary| (summary.latest_block_root, summary.latest_block_slot))
            .unique()
    }

    /// Returns a vec of state summaries that have an unknown parent when forming the DAG tree
    pub fn tree_roots(&self) -> Vec<(Hash256, DAGStateSummary)> {
        self.state_summaries_by_state_root
            .iter()
            .filter_map(|(state_root, summary)| {
                if self
                    .state_summaries_by_state_root
                    .contains_key(&summary.previous_state_root)
                {
                    // Summaries with a known parent are not roots
                    None
                } else {
                    Some((*state_root, *summary))
                }
            })
            .collect()
    }

    pub fn summaries_count(&self) -> usize {
        self.state_summaries_by_block_root
            .values()
            .map(|s| s.len())
            .sum()
    }

    pub fn summaries_by_slot_ascending(&self) -> BTreeMap<Slot, Vec<(Hash256, DAGStateSummary)>> {
        let mut summaries = BTreeMap::<Slot, Vec<_>>::new();
        for (state_root, summary) in self.state_summaries_by_state_root.iter() {
            summaries
                .entry(summary.slot)
                .or_default()
                .push((*state_root, *summary));
        }
        summaries
    }

    pub fn previous_state_root(&self, state_root: Hash256) -> Result<Hash256, Error> {
        let summary = self
            .state_summaries_by_state_root
            .get(&state_root)
            .ok_or(Error::MissingStateSummary(state_root))?;
        if summary.previous_state_root == Hash256::ZERO {
            Err(Error::RootUnknownPreviousStateRoot(
                summary.slot,
                state_root,
            ))
        } else {
            Ok(summary.previous_state_root)
        }
    }

    pub fn ancestor_state_root_at_slot(
        &self,
        starting_state_root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Hash256, Error> {
        let mut state_root = starting_state_root;
        // Walk backwards until we reach the state at `ancestor_slot`.
        loop {
            let summary = self
                .state_summaries_by_state_root
                .get(&state_root)
                .ok_or(Error::MissingStateSummary(state_root))?;

            // Assumes all summaries are contiguous
            match summary.slot.cmp(&ancestor_slot) {
                Ordering::Less => {
                    return Err(Error::RequestedSlotAboveSummary {
                        starting_state_root,
                        ancestor_slot,
                        state_root,
                        state_slot: summary.slot,
                    });
                }
                Ordering::Equal => {
                    return Ok(state_root);
                }
                Ordering::Greater => {
                    if summary.previous_state_root == Hash256::ZERO {
                        return Err(Error::RootUnknownAncestorStateRoot {
                            starting_state_root,
                            ancestor_slot,
                            root_state_root: state_root,
                            root_state_slot: summary.slot,
                        });
                    } else {
                        state_root = summary.previous_state_root;
                    }
                }
            }
        }
    }

    /// Returns all ancestors of `state_root` INCLUDING `state_root` until the next parent is not
    /// known.
    ///
    /// Post-Gloas this yields only one `state_root` per slot, either the Full or Pending state's
    /// root. If a full state is an ancestor of the starting state root, then that slot is full
    /// on the traversed chain, so the full state root is excluded (and the pending root excluded).
    pub fn ancestors_of(&self, mut state_root: Hash256) -> Result<Vec<(Hash256, Slot)>, Error> {
        // Sanity check that the first summary exists
        if !self.state_summaries_by_state_root.contains_key(&state_root) {
            return Err(Error::MissingStateSummary(state_root));
        }

        let mut ancestors = vec![];
        let mut last_slot = None;
        let mut skip_same_slot_allowed = true;
        loop {
            if let Some(summary) = self.state_summaries_by_state_root.get(&state_root) {
                // If this summary if the first summary with the same slot as the most recently
                // added summary, then we know that it's the Pending ancestor of the recently
                // processed Full state.  We can skip it, but we should not skip again.
                if let Some(last_slot) = last_slot
                    && summary.slot >= last_slot
                {
                    if summary.slot == last_slot
                        && skip_same_slot_allowed
                        && state_root != summary.previous_state_root
                    {
                        state_root = summary.previous_state_root;
                        skip_same_slot_allowed = false;
                        continue;
                    } else {
                        // Otherwise if the current state's slot is greater than the previous state,
                        // or we have already skipped a Pending state at this slot, it's a cycle.
                        return Err(Error::CircularAncestorChain {
                            state_root,
                            previous_state_root: summary.previous_state_root,
                            slot: summary.slot,
                            last_slot,
                        });
                    }
                }

                skip_same_slot_allowed = true;
                ancestors.push((state_root, summary.slot));
                last_slot = Some(summary.slot);
                state_root = summary.previous_state_root;
            } else {
                return Ok(ancestors);
            }
        }
    }

    /// Returns of the descendant state summaries roots given an initiail state root.
    pub fn descendants_of(&self, query_state_root: &Hash256) -> Result<Vec<Hash256>, Error> {
        let mut descendants = vec![];
        for child_root in self
            .child_state_roots
            .get(query_state_root)
            .ok_or(Error::MissingChildStateRoot(*query_state_root))?
        {
            descendants.push(*child_root);
            descendants.extend(self.descendants_of(child_root)?);
        }
        Ok(descendants)
    }

    /// Returns the root of the `Pending` state at `slot` with `latest_block_root`, if it exists.
    ///
    /// The `slot` must be the slot of the `latest_block_root` or a skipped slot following it. This
    /// function will not return the `state_root` of a state with a different `latest_block_root`
    /// even if it lies on the same chain.
    pub fn state_root_at_slot(&self, latest_block_root: Hash256, slot: Slot) -> Option<Hash256> {
        self.state_summaries_by_block_root
            .get(&latest_block_root)?
            .get(&slot)?
            .first()
            .map(|(state_root, _)| *state_root)
    }
}

impl From<HotStateSummary> for DAGStateSummary {
    fn from(value: HotStateSummary) -> Self {
        Self {
            slot: value.slot,
            latest_block_root: value.latest_block_root,
            latest_block_slot: value.latest_block_slot,
            previous_state_root: value.previous_state_root,
        }
    }
}
