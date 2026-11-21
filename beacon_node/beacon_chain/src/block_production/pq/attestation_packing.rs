use crate::{BeaconChainError, pq::attestation_preparation::PreparedAttestations};
use operation_pool::CompactIndexedAttestationPq;
use pq_prover::{Proof, Statement};
use ssz::ProgressiveBitList;
use state_processing::{
    ConsensusContext, VerifySignatures,
    common::get_attestation_participation_flag_indices,
    epoch_cache::initialize_epoch_cache,
    per_block_processing::{
        apply_parent_execution_payload_pq, verify_attestation_for_block_inclusion,
    },
    pq,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tree_hash::TreeHash;
use types::{
    AttestationData, AttestationPq, AttestationRef, BeaconState, ChainSpec, CommitteeBitsPq, Epoch,
    EthSpec, ExecutionRequestsPq, RelativeEpoch, XmssPublicKey,
    consts::altair::PARTICIPATION_FLAG_WEIGHTS,
};

type Credit = (Epoch, u64, usize);
type Credits = BTreeMap<Credit, u64>;
type Claim = (XmssPublicKey, [u8; 32], u64);
const INPUTS_PER_MERGE: usize = 16;

pub(crate) struct ProposalView<'a, E: EthSpec> {
    pre_parent: &'a BeaconState<E>,
    post_parent: BeaconState<E>,
    spec: &'a ChainSpec,
}

pub(crate) struct Packing<E: EthSpec> {
    pub(crate) attestations: Vec<AttestationPq<E>>,
    pub(crate) statements: Vec<Statement>,
    pub(crate) children: Vec<(Vec<Statement>, Proof)>,
    pub(crate) participation: u64,
    pub(crate) gained: u64,
    pub(crate) unique_claims: usize,
    pub(crate) single_committee: bool,
}

impl<'a, E: EthSpec> ProposalView<'a, E> {
    pub(crate) fn new(
        state: &'a BeaconState<E>,
        spec: &'a ChainSpec,
        parent_requests: Option<&ExecutionRequestsPq<E>>,
    ) -> Result<Self, BeaconChainError> {
        let mut post_parent = state.clone();
        if let Some(requests) = parent_requests {
            apply_parent_execution_payload_pq(&mut post_parent, requests, spec)
                .map_err(BeaconChainError::PrepareProposerFailed)?;
        }
        Ok(Self {
            pre_parent: state,
            post_parent,
            spec,
        })
    }

    pub(crate) fn with_reward_cache(mut self) -> Result<Self, BeaconChainError> {
        initialize_epoch_cache(&mut self.post_parent, self.spec)?;
        Ok(self)
    }

    fn statements(&self, attestation: &AttestationPq<E>) -> Option<Vec<Statement>> {
        let state = &self.post_parent;
        if attestation.data.slot
            > state
                .slot()
                .saturating_sub(pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ)
        {
            return None;
        }
        verify_attestation_for_block_inclusion(
            state,
            AttestationRef::Pq(attestation),
            &mut ConsensusContext::new(state.slot()),
            VerifySignatures::False,
            self.spec,
        )
        .ok()?;
        let pre = pq::attestation_statements(self.pre_parent, attestation, self.spec).ok()?;
        let post = pq::attestation_statements(state, attestation, self.spec).ok()?;
        (pre == post).then_some(pre)
    }

    fn flags(&self, data: &AttestationData) -> Option<impl AsRef<[usize]>> {
        let state = &self.post_parent;
        get_attestation_participation_flag_indices(
            state,
            data,
            Some(state.latest_block_header().slot),
            state.slot().as_u64().checked_sub(data.slot.as_u64())?,
            self.spec,
        )
        .ok()
    }

    pub(crate) fn bundle_is_valid(
        &self,
        attestations: &[AttestationPq<E>],
        statements: &[Statement],
    ) -> bool {
        let mut expected = statements.iter();
        attestations.iter().all(|attestation| {
            self.flags(&attestation.data).is_some()
                && self.statements(attestation).is_some_and(|actual| {
                    actual
                        .iter()
                        .all(|statement| expected.next() == Some(statement))
                })
        }) && expected.next().is_none()
    }

    fn credits(&self, attestation: &AttestationPq<E>) -> Option<Credits> {
        let state = &self.post_parent;
        let data = &attestation.data;
        let flags = self.flags(data)?;
        let credited =
            match RelativeEpoch::from_epoch(state.current_epoch(), data.target.epoch).ok()? {
                RelativeEpoch::Current => state.current_epoch_participation().ok()?,
                RelativeEpoch::Previous => state.previous_epoch_participation().ok()?,
                _ => return None,
            };
        let mut credits = BTreeMap::new();
        for index in pq::committee_attesters(state, attestation)
            .ok()?
            .into_iter()
            .flatten()
        {
            let current = credited.get(index as usize)?;
            let reward = state.get_base_reward(index as usize).ok()?;
            for &flag in flags.as_ref() {
                if !current.has_flag(flag).ok()? {
                    credits.insert(
                        (data.target.epoch, index, flag),
                        reward.checked_mul(*PARTICIPATION_FLAG_WEIGHTS.get(flag)?)?,
                    );
                }
            }
        }
        Some(credits)
    }

    pub(crate) fn bundle_credits(
        &self,
        attestations: &[AttestationPq<E>],
        statements: &[Statement],
    ) -> Option<Credits> {
        let mut output = Vec::new();
        let mut credits = BTreeMap::new();
        for attestation in attestations {
            output.extend(self.statements(attestation)?);
            credits.extend(self.credits(attestation)?);
        }
        (output == statements).then_some(credits)
    }

    pub(crate) fn select(
        &self,
        candidates: &[Arc<CompactIndexedAttestationPq<E>>],
        baseline: Option<&PreparedAttestations<E>>,
        single_only: bool,
        reference: bool,
    ) -> Option<Packing<E>> {
        let mut credits = if let Some(base) = baseline {
            self.bundle_credits(&base.attestations, &base.statements)?
        } else {
            BTreeMap::new()
        };
        let before = score(credits.values().copied());
        let mut claims: BTreeSet<Claim> = baseline
            .into_iter()
            .flat_map(|base| claims(&base.statements))
            .collect();
        let mut data = baseline
            .map(|base| {
                base.attestations
                    .iter()
                    .map(|a| &a.data)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut chosen = Vec::new();
        // Keep the additional scoring data bounded independently of the pool snapshot.
        // The allowance charges the BTree entries as well as their key and value.
        let mut credit_bytes = 0usize;
        let mut inputs = candidates
            .iter()
            .filter_map(|entry| {
                let statements = self.statements(&entry.attestation)?;
                if statements.as_slice() != std::slice::from_ref(&entry.statement) {
                    return None;
                }
                let gains = self.credits(&entry.attestation)?;
                let next = credit_bytes.saturating_add(gains.len().saturating_mul(64));
                if next > (16 << 20) {
                    return None;
                }
                credit_bytes = next;
                Some((entry, gains))
            })
            .collect::<Vec<_>>();
        let max_inputs = if single_only {
            1
        } else {
            INPUTS_PER_MERGE - usize::from(baseline.is_some())
        };
        for _ in 0..max_inputs {
            let winner = inputs
                .iter()
                .enumerate()
                .filter_map(|(index, (entry, gains))| {
                    if data.len() >= E::max_attestations_pq()
                        && !data.contains(&&entry.attestation.data)
                    {
                        return None;
                    }
                    let added = claims_of(&entry.statement)
                        .filter(|claim| !claims.contains(claim))
                        .count();
                    if added == 0
                        || (reference
                            && claims
                                .len()
                                .saturating_add(added)
                                .saturating_mul(pq_prover::XMSS_SIGNATURE_BYTES_LEN)
                                > E::max_stark_proof_size())
                    {
                        return None;
                    }
                    let gain = score(
                        gains
                            .iter()
                            .filter(|(key, _)| !credits.contains_key(key))
                            .map(|(_, weight)| *weight),
                    );
                    (gain > 0).then_some((gain, std::cmp::Reverse(index)))
                })
                .max();
            let Some((_, std::cmp::Reverse(index))) = winner else {
                break;
            };
            let (entry, gains) = inputs.remove(index);
            credits.extend(gains);
            claims.extend(claims_of(&entry.statement));
            let vote = &entry.attestation;
            if !data.contains(&&vote.data) {
                data.push(&vote.data);
            }
            inputs.retain(|(other, _)| {
                other.attestation.data != vote.data
                    || other.attestation.committee_bits != vote.committee_bits
            });
            chosen.push(entry);
        }

        if chosen.is_empty() {
            return None;
        }
        let mut votes = baseline
            .into_iter()
            .flat_map(|base| &base.attestations)
            .chain(chosen.iter().map(|entry| &entry.attestation));
        let attestations = pack_committee_bits(self.pre_parent, &mut votes)?;
        let statements = attestations
            .iter()
            .map(|attestation| self.statements(attestation))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let children = baseline
            .into_iter()
            .map(|base| {
                (
                    base.statements.clone(),
                    Proof::from_bytes(base.proof.to_vec()),
                )
            })
            .chain(chosen.into_iter().map(|entry| {
                (
                    vec![entry.statement.clone()],
                    Proof::from_bytes(entry.proof.to_vec()),
                )
            }))
            .collect();
        let participation = score(credits.into_values());
        let single_committee = [
            self.pre_parent.current_epoch(),
            self.pre_parent.previous_epoch(),
        ]
        .into_iter()
        .all(|epoch| {
            self.pre_parent
                .get_committee_count_at_slot(epoch.start_slot(E::slots_per_epoch()))
                == Ok(1)
        });
        Some(Packing {
            attestations,
            statements,
            children,
            participation,
            gained: participation.saturating_sub(before),
            unique_claims: claims.len(),
            single_committee,
        })
    }
}

fn score(weights: impl Iterator<Item = u64>) -> u64 {
    weights.fold(0, u64::saturating_add)
}

pub(crate) fn participation(credits: Credits) -> u64 {
    score(credits.into_values())
}

fn claims(statements: &[Statement]) -> impl Iterator<Item = Claim> + '_ {
    statements.iter().flat_map(claims_of)
}

fn claims_of(statement: &Statement) -> impl Iterator<Item = Claim> + '_ {
    statement
        .pubkeys
        .iter()
        .map(|key| (*key, statement.message, statement.leaf_index))
}

fn pack_committee_bits<'a, E: EthSpec>(
    state: &BeaconState<E>,
    votes: impl Iterator<Item = &'a AttestationPq<E>>,
) -> Option<Vec<AttestationPq<E>>> {
    let mut records: Vec<(AttestationData, BTreeMap<u64, Vec<bool>>)> = Vec::new();
    for vote in votes {
        let record = match records.iter().position(|(data, _)| *data == vote.data) {
            Some(index) => records.get_mut(index)?,
            None => {
                records.push((vote.data.clone(), BTreeMap::new()));
                records.last_mut()?
            }
        };
        let mut bits = vote.aggregation_bits.iter();
        for committee in vote.get_committee_indices() {
            let len = state
                .get_beacon_committee(vote.data.slot, committee)
                .ok()?
                .committee
                .len();
            let union = record
                .1
                .entry(committee)
                .or_insert_with(|| vec![false; len]);
            for position in union {
                *position |= bits.next()?;
            }
        }
        if bits.next().is_some() {
            return None;
        }
    }
    records.sort_by_key(|(data, _)| (data.slot, data.tree_hash_root()));
    records
        .into_iter()
        .map(|(data, committees)| {
            let mut committee_bits = CommitteeBitsPq::<E>::default();
            let mut aggregation_bits =
                ProgressiveBitList::with_capacity(committees.values().map(Vec::len).sum());
            let mut position = 0;
            for (committee, bits) in committees {
                committee_bits.set(committee as usize, true).ok()?;
                for bit in bits {
                    if bit {
                        aggregation_bits.set(position, true).ok()?;
                    }
                    position += 1;
                }
            }
            Some(AttestationPq {
                data,
                committee_bits,
                aggregation_bits,
            })
        })
        .collect()
}
