use crate::{
    LightClientStore, LightClientStoreSchema, LightClientSyncError, beacon_header,
    header::validate_finalized_light_client_header, merkle::is_valid_normalized_merkle_branch,
    validate_light_client_header,
};
use bls::{PublicKeyBytes, SignatureSet};
use safe_arith::{ArithError, SafeArith};
use std::borrow::Cow;
use tree_hash::TreeHash;
use types::{
    ChainSpec, Domain, EthSpec, ForkName, Hash256, LightClientHeader, LightClientUpdate,
    SignedRoot, Slot,
    light_client::consts::{
        FINALIZED_ROOT_INDEX, FINALIZED_ROOT_INDEX_ELECTRA, FINALIZED_ROOT_PROOF_LEN,
        FINALIZED_ROOT_PROOF_LEN_ELECTRA, NEXT_SYNC_COMMITTEE_INDEX,
        NEXT_SYNC_COMMITTEE_INDEX_ELECTRA, NEXT_SYNC_COMMITTEE_PROOF_LEN,
        NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
    },
};

/// An update validated against one particular store and chain specification.
///
/// The exclusive store borrow prevents the store from changing before processing. The update
/// and specification remain immutably borrowed too. This token is not a finalized checkpoint:
/// it only attests that the update passed validation, potentially with minority participation.
/// Dropping it leaves the store unchanged. It has no public constructor or `Clone` implementation.
///
/// A pending validation result prevents another mutable borrow of its store:
///
/// ```compile_fail,E0499
/// use decentralized_checkpoint_sync::{LightClientStore, validate_light_client_update};
/// use types::{ChainSpec, ForkName, Hash256, LightClientUpdate, MinimalEthSpec, Slot};
///
/// fn validate_twice(store: &mut LightClientStore<MinimalEthSpec>,
///     update: &LightClientUpdate<MinimalEthSpec>, spec: &ChainSpec) {
///     let pending = validate_light_client_update(store, update, ForkName::Altair,
///         Slot::new(10), Hash256::default(), spec);
///     let second = validate_light_client_update(store, update, ForkName::Altair,
///         Slot::new(10), Hash256::default(), spec);
///     drop(pending);
/// }
/// ```
///
/// The update cannot change while the token exists:
///
/// ```compile_fail,E0506
/// use decentralized_checkpoint_sync::{LightClientStore, validate_light_client_update};
/// use types::{ChainSpec, ForkName, Hash256, LightClientUpdate, MinimalEthSpec, Slot};
///
/// fn replace_update(store: &mut LightClientStore<MinimalEthSpec>,
///     update: &mut LightClientUpdate<MinimalEthSpec>,
///     replacement: LightClientUpdate<MinimalEthSpec>, spec: &ChainSpec) {
///     let pending = validate_light_client_update(store, update, ForkName::Altair,
///         Slot::new(10), Hash256::default(), spec);
///     *update = replacement;
///     drop(pending);
/// }
/// ```
#[derive(Debug)]
pub struct ValidatedLightClientUpdate<'store, 'update, E: EthSpec> {
    store: &'store mut LightClientStore<E>,
    update: &'update LightClientUpdate<E>,
    spec: &'store ChainSpec,
    data_fork: ForkName,
}

impl<E: EthSpec> ValidatedLightClientUpdate<'_, '_, E> {
    pub fn store(&self) -> &LightClientStore<E> {
        self.store
    }

    pub fn update(&self) -> &LightClientUpdate<E> {
        self.update
    }

    pub fn chain_spec(&self) -> &ChainSpec {
        self.spec
    }

    pub fn data_fork(&self) -> ForkName {
        self.data_fork
    }
}

/// Validate an untrusted update, without modifying the store on either success or failure.
///
/// The mutable borrow binds the resulting token to this store for subsequent processing; it
/// does not permit callers to bypass validation or promote the update directly into finality.
/// `data_fork` is the decoded (or locally upgraded) update format. `current_slot`, the genesis
/// validators root and the chain specification must come from the caller's trusted context.
///
/// Implements [consensus-specs v1.7.0-alpha.14 validation], including Electra normalized branches.
///
/// [consensus-specs v1.7.0-alpha.14 validation]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#validate_light_client_update
pub fn validate_light_client_update<'store, 'update, E: EthSpec>(
    store: &'store mut LightClientStore<E>,
    update: &'update LightClientUpdate<E>,
    data_fork: ForkName,
    current_slot: Slot,
    genesis_validators_root: Hash256,
    spec: &'store ChainSpec,
) -> Result<ValidatedLightClientUpdate<'store, 'update, E>, LightClientSyncError> {
    let update_schema = LightClientStoreSchema::try_from(data_fork)?;
    if update_schema > store.store_schema() {
        return Err(LightClientSyncError::UpdateSchemaTooNew {
            update_schema,
            store_schema: store.store_schema(),
        });
    }

    let aggregate = update.sync_aggregate();
    let participants = aggregate.num_set_bits();
    let participant_count = u64::try_from(participants).map_err(|_| ArithError::Overflow)?;
    if participant_count < spec.min_sync_committee_participants {
        return Err(LightClientSyncError::InsufficientParticipants {
            actual: participants,
            minimum: spec.min_sync_committee_participants,
        });
    }

    let view = UpdateView::new(update);
    validate_light_client_header(&view.attested_header, data_fork, spec)?;
    let attested = beacon_header(&view.attested_header);
    let finalized = beacon_header(&view.finalized_header);
    let signature_slot = *update.signature_slot();
    if !(current_slot >= signature_slot
        && signature_slot > attested.slot
        && attested.slot >= finalized.slot)
    {
        return Err(LightClientSyncError::InvalidUpdateSlots {
            current_slot,
            signature_slot,
            attested_slot: attested.slot,
            finalized_slot: finalized.slot,
        });
    }

    let store_slot = beacon_header(store.spec_finalized_header()).slot;
    let store_period = sync_committee_period::<E>(store_slot, spec)?;
    let signature_period = sync_committee_period::<E>(signature_slot, spec)?;
    let next_committee = store.next_sync_committee();
    let signature_in_next_period = signature_period.checked_sub(store_period) == Some(1);
    if signature_period != store_period && !(next_committee.is_some() && signature_in_next_period) {
        return Err(LightClientSyncError::InvalidSignaturePeriod {
            store_period,
            signature_period,
        });
    }

    // The existing types helper also checks periods for update ranking. The validation spec
    // determines presence solely from the branch, including signatures crossing a period boundary.
    let has_next_committee = view
        .next_committee_branch
        .iter()
        .any(|node| *node != Hash256::default());
    let has_finality = view
        .finality_branch
        .iter()
        .any(|node| *node != Hash256::default());
    let attested_period = sync_committee_period::<E>(attested.slot, spec)?;
    let supplies_missing_committee =
        next_committee.is_none() && has_next_committee && attested_period == store_period;
    if attested.slot <= store_slot && !supplies_missing_committee {
        return Err(LightClientSyncError::IrrelevantUpdate);
    }

    let attested_fork = spec.fork_name_at_slot::<E>(attested.slot);
    let (finality_index, finality_depth, committee_index, committee_depth) =
        if attested_fork.electra_enabled() {
            (
                FINALIZED_ROOT_INDEX_ELECTRA,
                FINALIZED_ROOT_PROOF_LEN_ELECTRA,
                NEXT_SYNC_COMMITTEE_INDEX_ELECTRA,
                NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
            )
        } else {
            (
                FINALIZED_ROOT_INDEX,
                FINALIZED_ROOT_PROOF_LEN,
                NEXT_SYNC_COMMITTEE_INDEX,
                NEXT_SYNC_COMMITTEE_PROOF_LEN,
            )
        };

    if !has_finality {
        if !view.finalized_is_default {
            return Err(LightClientSyncError::NonDefaultFinalizedHeader);
        }
    } else {
        let finalized_root = if finalized.slot == 0 {
            // Genesis finality is represented by a default header and ZERO root, including on
            // networks where slot zero predates Altair. It is not an ordinary header to validate.
            if !view.finalized_is_default {
                return Err(LightClientSyncError::NonDefaultFinalizedHeader);
            }
            Hash256::default()
        } else {
            validate_finalized_light_client_header(&view.finalized_header, data_fork, spec)?;
            finalized.canonical_root()
        };
        if !is_valid_normalized_merkle_branch(
            finalized_root,
            view.finality_branch,
            finality_index,
            finality_depth,
            attested.state_root,
        ) {
            return Err(LightClientSyncError::InvalidFinalityProof);
        }
    }

    let update_committee = update.next_sync_committee().as_ref();
    if !has_next_committee {
        if update_committee.aggregate_pubkey != PublicKeyBytes::empty()
            || update_committee
                .pubkeys
                .iter()
                .any(|key| *key != PublicKeyBytes::empty())
        {
            return Err(LightClientSyncError::NonDefaultNextSyncCommittee);
        }
    } else {
        if attested_period == store_period
            && let Some(known_committee) = next_committee
            && update_committee != known_committee
        {
            return Err(LightClientSyncError::NextSyncCommitteeMismatch);
        }
        if !is_valid_normalized_merkle_branch(
            update_committee.tree_hash_root(),
            view.next_committee_branch,
            committee_index,
            committee_depth,
            attested.state_root,
        ) {
            return Err(LightClientSyncError::InvalidNextSyncCommitteeProof);
        }
    }

    let committee = if signature_period == store_period {
        store.current_sync_committee()
    } else {
        next_committee.ok_or(LightClientSyncError::InvalidSignaturePeriod {
            store_period,
            signature_period,
        })?
    };
    let mut pubkeys = Vec::with_capacity(participants);
    for (index, (participated, pubkey)) in aggregate
        .sync_committee_bits
        .iter()
        .zip(committee.pubkeys.iter())
        .enumerate()
    {
        if participated {
            pubkeys.push(Cow::Owned(pubkey.decompress().map_err(|_| {
                LightClientSyncError::InvalidSyncCommitteePublicKey { index }
            })?));
        }
    }

    let fork_slot = Slot::new(signature_slot.as_u64().saturating_sub(1));
    let signature_fork = spec.fork_name_at_slot::<E>(fork_slot);
    LightClientStoreSchema::try_from(signature_fork)?;
    let domain = spec.compute_domain(
        Domain::SyncCommittee,
        spec.fork_version_for_name(signature_fork),
        genesis_validators_root,
    );
    let signing_root = attested.signing_root(domain);
    if !SignatureSet::multiple_pubkeys(&aggregate.sync_committee_signature, pubkeys, signing_root)
        .verify()
    {
        return Err(LightClientSyncError::InvalidSyncCommitteeSignature);
    }

    Ok(ValidatedLightClientUpdate {
        store,
        update,
        spec,
        data_fork,
    })
}

fn sync_committee_period<E: EthSpec>(slot: Slot, spec: &ChainSpec) -> Result<u64, ArithError> {
    slot.as_u64()
        .safe_div(E::slots_per_epoch())?
        .safe_div(spec.epochs_per_sync_committee_period.as_u64())
}

/// The header variants are retained so upgraded headers keep their full default-field semantics.
struct UpdateView<'a, E: EthSpec> {
    attested_header: LightClientHeader<E>,
    finalized_header: LightClientHeader<E>,
    finalized_is_default: bool,
    finality_branch: &'a [Hash256],
    next_committee_branch: &'a [Hash256],
}

impl<'a, E: EthSpec> UpdateView<'a, E> {
    fn new(update: &'a LightClientUpdate<E>) -> Self {
        macro_rules! view {
            ($inner:ident, $variant:ident) => {
                Self {
                    attested_header: LightClientHeader::$variant($inner.attested_header.clone()),
                    finalized_header: LightClientHeader::$variant($inner.finalized_header.clone()),
                    finalized_is_default: $inner.finalized_header == Default::default(),
                    finality_branch: $inner.finality_branch.as_ref(),
                    next_committee_branch: $inner.next_sync_committee_branch.as_ref(),
                }
            };
        }
        match update {
            LightClientUpdate::Altair(inner) => view!(inner, Altair),
            LightClientUpdate::Capella(inner) => view!(inner, Capella),
            LightClientUpdate::Deneb(inner) => view!(inner, Deneb),
            LightClientUpdate::Electra(inner) => view!(inner, Electra),
            LightClientUpdate::Fulu(inner) => view!(inner, Fulu),
        }
    }
}

#[cfg(test)]
mod tests;
