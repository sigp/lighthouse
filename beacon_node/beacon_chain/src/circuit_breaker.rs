//! The post-Gloas builder circuit breaker.
//!
//! After Gloas (ePBS) a proposer commits to a builder's *bid* and the builder is expected to
//! reveal the corresponding execution payload later in the slot. Builder failures therefore show
//! up as beacon blocks whose payloads never land, not as missed slots. This module decides when
//! external bids should be ignored in favour of the local build:
//!
//! - **Skip rules**: too many missed payloads in a row, or too many in the last `SLOTS_PER_EPOCH`
//!   slots, on the chain being extended. A "missed payload" is a slot that has a beacon block but
//!   whose execution payload was never applied. Slots with no beacon block at all are a validator
//!   or network failure and are not counted.
//! - **Builder bans**: a builder that fails to reveal the payload for a block that received enough
//!   attestations to charge it is banned for at least an epoch. A ban is tied to the offending
//!   block, so it only applies to proposals whose chain contains that block.
//!
//! Everything here is node-local policy. Nothing affects block validity or fork choice.
//!
//! The pre-Gloas circuit breaker, which counts missed *slots*, lives in
//! [`BeaconChain::is_healthy_pre_gloas`](crate::BeaconChain::is_healthy_pre_gloas) and is unchanged.

use std::collections::HashMap;

use bls::PublicKeyBytes;
use execution_layer::FailedCondition;
use parking_lot::RwLock;
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::{BeaconState, BeaconStateError, BuilderIndex, ChainSpec, EthSpec, Hash256, Slot};

use crate::chain_config::ChainConfig;

/// Configuration for the circuit breaker. Derived from [`ChainConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// Maximum tolerated missed payloads in a row before the proposal slot.
    pub skips: usize,
    /// Maximum tolerated missed payloads in the `SLOTS_PER_EPOCH` slots before the proposal slot.
    pub skips_per_epoch: usize,
    /// How many slots a builder is banned for after a missed reveal.
    pub ban_slots: u64,
    /// Bypass every check: external bids are always considered and no builder is ever banned.
    pub disable_checks: bool,
}

impl CircuitBreakerConfig {
    pub fn from_chain_config(chain_config: &ChainConfig) -> Self {
        Self {
            skips: chain_config.builder_fallback_skips,
            skips_per_epoch: chain_config.builder_fallback_skips_per_epoch,
            ban_slots: chain_config.builder_fallback_ban_slots,
            disable_checks: chain_config.builder_fallback_disable_checks,
        }
    }
}

/// What happened in one slot on the chain a state describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatus {
    /// No beacon block was proposed in this slot.
    NoBlock,
    /// A beacon block landed but its execution payload was never applied to the chain.
    PayloadMissing,
    /// A beacon block landed and so did its execution payload.
    PayloadPresent,
}

/// The result of recording an offence with [`CircuitBreaker::ban_builder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanOutcome {
    /// A new entry was recorded.
    New,
    /// This offending block was already recorded for this builder; nothing changed.
    AlreadyRecorded,
}

/// One recorded offence: the builder failed to reveal the payload for the block identified by
/// `block_root` / `block_slot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanEntry {
    pub block_root: Hash256,
    pub block_slot: Slot,
    /// The first slot at which this entry no longer applies.
    pub expires_at: Slot,
}

/// See the [module docs](self).
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    /// Offences per builder pubkey: one entry per offending block, never merged. Each `Vec` is
    /// bounded by the number of misses inside one ban window (normally one) and is dropped when
    /// it empties.
    ///
    /// This lock is a leaf: it is never held while another lock is taken.
    banned: RwLock<HashMap<PublicKeyBytes, Vec<BanEntry>>>,
}

impl CircuitBreaker {
    /// Create a circuit breaker. `ban_slots` is raised to at least `E::slots_per_epoch()`.
    pub fn new<E: EthSpec>(mut config: CircuitBreakerConfig) -> Self {
        config.ban_slots = config.ban_slots.max(E::slots_per_epoch());
        Self {
            config,
            banned: RwLock::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    pub fn disable_checks(&self) -> bool {
        self.config.disable_checks
    }

    /// Evaluate the two skip rules on pre-computed counts.
    ///
    /// Returns the first rule that tripped: `Skips` (too many missed payloads in a row) takes
    /// priority over `SkipsPerEpoch`. Always `None` when checks are disabled.
    pub fn evaluate_skips(
        &self,
        consecutive_missed: usize,
        window_missed: usize,
    ) -> Option<FailedCondition> {
        if self.config.disable_checks {
            None
        } else if consecutive_missed > self.config.skips {
            Some(FailedCondition::Skips)
        } else if window_missed > self.config.skips_per_epoch {
            Some(FailedCondition::SkipsPerEpoch)
        } else {
            None
        }
    }

    /// Evaluate the two skip rules against the chain described by `state`.
    ///
    /// `state` must be the Gloas production state, advanced to `produce_at_slot` on the parent
    /// being extended, with the parent's payload availability bit already set if building on
    /// FULL. Returns `None` without touching the state when checks are disabled.
    pub fn evaluate_skips_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        produce_at_slot: Slot,
    ) -> Result<Option<FailedCondition>, BeaconStateError> {
        if self.config.disable_checks {
            return Ok(None);
        }
        if state.slot() != produce_at_slot {
            return Err(BeaconStateError::SlotOutOfBounds);
        }
        let consecutive_missed =
            count_consecutive_missed_payloads(state, produce_at_slot, self.config.skips)?;
        let window_missed = count_missed_payloads_in_window(state, produce_at_slot)?;
        Ok(self.evaluate_skips(consecutive_missed, window_missed))
    }

    /// Record that `pubkey` failed to reveal the payload for the block at `block_root` /
    /// `block_slot`, detected at `detected_at`. The entry expires `ban_slots` after detection.
    ///
    /// Existing entries for the same builder are never modified: a second offence adds a second
    /// entry with its own expiry. Recording the same offending block twice is a no-op.
    pub fn ban_builder(
        &self,
        pubkey: PublicKeyBytes,
        block_root: Hash256,
        block_slot: Slot,
        detected_at: Slot,
    ) -> BanOutcome {
        let mut banned = self.banned.write();
        let entries = banned.entry(pubkey).or_default();
        if entries.iter().any(|entry| entry.block_root == block_root) {
            return BanOutcome::AlreadyRecorded;
        }
        entries.push(BanEntry {
            block_root,
            block_slot,
            expires_at: detected_at.saturating_add(self.config.ban_slots),
        });
        BanOutcome::New
    }

    /// Returns `true` if bids from `pubkey` must be ignored for a proposal at `slot` on the chain
    /// described by `state`.
    ///
    /// `state` is the production state advanced to `slot` on the parent being extended. An entry
    /// applies only if its offending block is an ancestor of that parent, i.e. the block root the
    /// state records at `block_slot` equals the entry's root. A block we re-orged away from
    /// therefore stops banning, and one we re-org back to bans again.
    pub fn is_banned<E: EthSpec>(
        &self,
        pubkey: &PublicKeyBytes,
        state: &BeaconState<E>,
        slot: Slot,
    ) -> bool {
        self.is_banned_with(pubkey, slot, |entry| {
            match state.get_block_root(entry.block_slot) {
                Ok(root) => *root == entry.block_root,
                // Older than `SLOTS_PER_HISTORICAL_ROOT`: long finalized, hence on every chain we
                // could be extending. Only reachable with a ban length above 8192 slots.
                Err(_) => true,
            }
        })
    }

    /// Core of [`Self::is_banned`] with the chain view supplied by the caller: `true` if any
    /// unexpired entry for `pubkey` has an offending block that `is_canonical` accepts.
    ///
    /// Always `false` when checks are disabled.
    pub fn is_banned_with(
        &self,
        pubkey: &PublicKeyBytes,
        slot: Slot,
        is_canonical: impl Fn(&BanEntry) -> bool,
    ) -> bool {
        if self.config.disable_checks {
            return false;
        }
        self.banned.read().get(pubkey).is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| slot < entry.expires_at && is_canonical(entry))
        })
    }

    /// Drop every entry that has expired at `current_slot`, and every builder left with none.
    pub fn prune(&self, current_slot: Slot) {
        self.banned.write().retain(|_, entries| {
            entries.retain(|entry| entry.expires_at > current_slot);
            !entries.is_empty()
        });
    }

    /// The number of unexpired ban entries (canonicity is not evaluated).
    pub fn num_ban_entries(&self) -> usize {
        self.banned.read().values().map(Vec::len).sum()
    }
}

/// Classify `slot` on the chain described by the Gloas `state`.
///
/// Requires `slot < state.slot()`. The genesis slot always has a block and a payload.
pub fn slot_status<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<SlotStatus, BeaconStateError> {
    // Reading the availability bit first makes a pre-Gloas state an `IncorrectStateVariant`
    // error rather than a silently wrong classification.
    let availability = state.execution_payload_availability()?;

    let block_present = if slot == 0 {
        true
    } else {
        state.get_block_root(slot)? != state.get_block_root(slot.saturating_sub(1u64))?
    };
    if !block_present {
        return Ok(SlotStatus::NoBlock);
    }

    let payload_present = if slot == 0 {
        true
    } else {
        availability
            .get(slot.as_usize() % E::slots_per_historical_root())
            .map_err(|_| BeaconStateError::InvalidBitfield)?
    };
    Ok(if payload_present {
        SlotStatus::PayloadPresent
    } else {
        SlotStatus::PayloadMissing
    })
}

/// Count how many blocks in a row, walking back from `produce_at_slot - 1`, had a missed payload.
///
/// Slots with no block are skipped over; the walk stops at the first block whose payload landed,
/// once the count exceeds `limit`, or when the state's block-root history runs out.
pub fn count_consecutive_missed_payloads<E: EthSpec>(
    state: &BeaconState<E>,
    produce_at_slot: Slot,
    limit: usize,
) -> Result<usize, BeaconStateError> {
    let mut count = 0;
    for slot in (0..produce_at_slot.as_u64()).rev() {
        match slot_status(state, Slot::new(slot)) {
            Ok(SlotStatus::NoBlock) => continue,
            Ok(SlotStatus::PayloadMissing) => {
                count += 1;
                if count > limit {
                    break;
                }
            }
            Ok(SlotStatus::PayloadPresent) => break,
            // The state's `block_roots` history is exhausted.
            Err(BeaconStateError::SlotOutOfBounds) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(count)
}

/// Count missed payloads in the `SLOTS_PER_EPOCH` slots before `produce_at_slot`.
pub fn count_missed_payloads_in_window<E: EthSpec>(
    state: &BeaconState<E>,
    produce_at_slot: Slot,
) -> Result<usize, BeaconStateError> {
    let window_start = produce_at_slot.saturating_sub(E::slots_per_epoch());
    let mut count = 0;
    for slot in window_start.as_u64()..produce_at_slot.as_u64() {
        if slot_status(state, Slot::new(slot))? == SlotStatus::PayloadMissing {
            count += 1;
        }
    }
    Ok(count)
}

/// The attestation weight a block must reach for its builder to be charged: the spec's builder
/// payment quorum, `total / SLOTS_PER_EPOCH * numerator / denominator`.
///
/// `None` on arithmetic overflow or a zero denominator.
pub fn builder_payment_quorum<E: EthSpec>(
    total_effective_balance: u64,
    spec: &ChainSpec,
) -> Option<u64> {
    total_effective_balance
        .checked_div(E::slots_per_epoch())?
        .checked_mul(spec.builder_payment_threshold_numerator)?
        .checked_div(spec.builder_payment_threshold_denominator)
}

/// Decide whether a builder should be banned for the block whose bid it won.
///
/// A ban requires an external builder, no payload received locally, no PTC majority saying the
/// payload was timely (which would mean it was revealed and only we missed it), and enough
/// attestation weight on the block that the builder is charged for it.
pub fn should_ban_for_missed_reveal(
    builder_index: BuilderIndex,
    payload_received: bool,
    ptc_votes_timely: bool,
    block_weight: Option<u64>,
    quorum: u64,
) -> bool {
    builder_index != BUILDER_INDEX_SELF_BUILD
        && !payload_received
        && !ptc_votes_timely
        && block_weight.is_some_and(|weight| weight >= quorum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use types::{
        ExecutionBlockHash, ExecutionPayloadHeader, ExecutionPayloadHeaderFulu, ForkName,
        MinimalEthSpec,
    };

    type E = MinimalEthSpec;
    const SPE: u64 = 8; // MinimalEthSpec::slots_per_epoch()

    fn config(skips: usize, skips_per_epoch: usize) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            skips,
            skips_per_epoch,
            ban_slots: 32,
            disable_checks: false,
        }
    }

    fn breaker(skips: usize, skips_per_epoch: usize) -> CircuitBreaker {
        CircuitBreaker::new::<E>(config(skips, skips_per_epoch))
    }

    fn pubkey(byte: u8) -> PublicKeyBytes {
        let mut bytes = [0u8; 48];
        bytes[0] = byte;
        PublicKeyBytes::deserialize(&bytes).unwrap()
    }

    fn root(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    fn gloas_genesis_state() -> (BeaconState<E>, ChainSpec) {
        let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
        let keypairs = generate_deterministic_keypairs(64);
        let header = ExecutionPayloadHeader::Fulu(ExecutionPayloadHeaderFulu {
            block_hash: ExecutionBlockHash::repeat_byte(0x42),
            gas_limit: 30_000_000,
            ..Default::default()
        });
        let state = interop_genesis_state::<E>(
            &keypairs,
            0,
            Hash256::repeat_byte(0x42),
            Some(header),
            &spec,
        )
        .expect("should build Gloas genesis state");
        (state, spec)
    }

    /// Build a state at `slot` whose history is described by `history`: one `Option<bool>` per
    /// slot `1..slot`, `None` for no block, `Some(payload_present)` for a block.
    fn state_with_history(history: &[Option<bool>]) -> BeaconState<E> {
        let (mut state, _spec) = gloas_genesis_state();
        let slot = Slot::new(history.len() as u64 + 1);
        *state.slot_mut() = slot;

        let genesis_root = root(0xaa);
        state.set_block_root(Slot::new(0), genesis_root).unwrap();
        let mut latest_root = genesis_root;
        for (i, entry) in history.iter().enumerate() {
            let s = Slot::new(i as u64 + 1);
            if let Some(payload_present) = entry {
                latest_root = root(s.as_u64() as u8 + 1);
                state
                    .execution_payload_availability_mut()
                    .unwrap()
                    .set(
                        s.as_usize() % E::slots_per_historical_root(),
                        *payload_present,
                    )
                    .unwrap();
            }
            state.set_block_root(s, latest_root).unwrap();
        }
        state
    }

    // --- skip rules -------------------------------------------------------------------------

    #[test]
    fn evaluate_skips_boundaries() {
        let cb = breaker(3, 8);
        assert_eq!(cb.evaluate_skips(0, 0), None);
        assert_eq!(cb.evaluate_skips(3, 0), None);
        assert_eq!(cb.evaluate_skips(4, 0), Some(FailedCondition::Skips));
        assert_eq!(cb.evaluate_skips(0, 8), None);
        assert_eq!(
            cb.evaluate_skips(0, 9),
            Some(FailedCondition::SkipsPerEpoch)
        );
        // Consecutive takes priority when both trip.
        assert_eq!(cb.evaluate_skips(4, 9), Some(FailedCondition::Skips));
    }

    #[test]
    fn evaluate_skips_disabled() {
        let cb = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            disable_checks: true,
            ..config(0, 0)
        });
        assert_eq!(cb.evaluate_skips(100, 100), None);
    }

    #[test]
    fn slot_status_classification() {
        // slots: 1 present, 2 missing, 3 no block, 4 missing
        let state = state_with_history(&[Some(true), Some(false), None, Some(false)]);
        assert_eq!(
            slot_status(&state, Slot::new(0)).unwrap(),
            SlotStatus::PayloadPresent
        );
        assert_eq!(
            slot_status(&state, Slot::new(1)).unwrap(),
            SlotStatus::PayloadPresent
        );
        assert_eq!(
            slot_status(&state, Slot::new(2)).unwrap(),
            SlotStatus::PayloadMissing
        );
        assert_eq!(
            slot_status(&state, Slot::new(3)).unwrap(),
            SlotStatus::NoBlock
        );
        assert_eq!(
            slot_status(&state, Slot::new(4)).unwrap(),
            SlotStatus::PayloadMissing
        );
        // The current slot is not readable.
        assert!(matches!(
            slot_status(&state, state.slot()),
            Err(BeaconStateError::SlotOutOfBounds)
        ));
    }

    #[test]
    fn slot_status_rejects_pre_gloas_state() {
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let keypairs = generate_deterministic_keypairs(64);
        let mut state =
            interop_genesis_state::<E>(&keypairs, 0, Hash256::repeat_byte(0x42), None, &spec)
                .unwrap();
        *state.slot_mut() = Slot::new(2);
        assert!(matches!(
            slot_status(&state, Slot::new(1)),
            Err(BeaconStateError::IncorrectStateVariant)
        ));
    }

    #[test]
    fn consecutive_missed_skips_empty_slots_and_stops_at_present() {
        // slots 1..=6: present, missing, none, missing, none, missing  -> 3 in a row
        let state = state_with_history(&[
            Some(true),
            Some(false),
            None,
            Some(false),
            None,
            Some(false),
        ]);
        let produce_at = state.slot();
        assert_eq!(
            count_consecutive_missed_payloads(&state, produce_at, 100).unwrap(),
            3
        );
        // Stops early once the limit is exceeded.
        assert_eq!(
            count_consecutive_missed_payloads(&state, produce_at, 1).unwrap(),
            2
        );
    }

    #[test]
    fn consecutive_missed_is_zero_when_latest_payload_present() {
        let state = state_with_history(&[Some(false), Some(false), None, Some(true)]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, state.slot(), 100).unwrap(),
            0
        );
    }

    #[test]
    fn consecutive_missed_ignores_empty_slots_entirely() {
        // Only empty slots after the last present payload: not a builder failure.
        let state = state_with_history(&[Some(true), None, None, None, None]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, state.slot(), 100).unwrap(),
            0
        );
    }

    #[test]
    fn consecutive_missed_walks_back_to_genesis() {
        // Every block since genesis missed its payload; genesis itself counts as present.
        let state = state_with_history(&[Some(false), Some(false)]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, state.slot(), 100).unwrap(),
            2
        );
    }

    #[test]
    fn window_counts_only_missed_payloads_in_last_epoch() {
        // 12 slots of history; window is the last SPE (8) slots: 5..=12.
        // slots 1..=4 (outside window): missing, missing, missing, missing
        // slots 5..=12 (inside):        missing, none, present, missing, none, none, missing, present
        let state = state_with_history(&[
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            None,
            Some(true),
            Some(false),
            None,
            None,
            Some(false),
            Some(true),
        ]);
        let produce_at = state.slot();
        assert_eq!(produce_at, Slot::new(13));
        assert_eq!(
            count_missed_payloads_in_window(&state, produce_at).unwrap(),
            3
        );
    }

    #[test]
    fn window_saturates_at_genesis() {
        let state = state_with_history(&[Some(false), Some(false)]);
        assert_eq!(
            count_missed_payloads_in_window(&state, state.slot()).unwrap(),
            2
        );
    }

    #[test]
    fn evaluate_skips_for_state_end_to_end() {
        let state = state_with_history(&[Some(true), Some(false), None, Some(false), Some(false)]);
        let slot = state.slot();
        // 3 in a row, 4 in the window.
        assert_eq!(
            breaker(3, 8)
                .evaluate_skips_for_state(&state, slot)
                .unwrap(),
            None
        );
        assert_eq!(
            breaker(2, 8)
                .evaluate_skips_for_state(&state, slot)
                .unwrap(),
            Some(FailedCondition::Skips)
        );
        assert_eq!(
            breaker(3, 2)
                .evaluate_skips_for_state(&state, slot)
                .unwrap(),
            Some(FailedCondition::SkipsPerEpoch)
        );
        // Wrong slot is rejected.
        assert!(
            breaker(3, 8)
                .evaluate_skips_for_state(&state, slot + 1)
                .is_err()
        );
        // Disabled checks never read the state.
        let disabled = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            disable_checks: true,
            ..config(0, 0)
        });
        assert_eq!(
            disabled.evaluate_skips_for_state(&state, slot + 1).unwrap(),
            None
        );
    }

    // --- bans -------------------------------------------------------------------------------

    #[test]
    fn ban_slots_clamped_to_slots_per_epoch() {
        let cb = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            ban_slots: 1,
            ..config(3, 8)
        });
        assert_eq!(cb.config().ban_slots, SPE);
        let cb = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            ban_slots: 64,
            ..config(3, 8)
        });
        assert_eq!(cb.config().ban_slots, 64);
    }

    #[test]
    fn ban_lifecycle() {
        let cb = breaker(3, 8);
        let pk = pubkey(1);
        let detected_at = Slot::new(10);
        assert_eq!(
            cb.ban_builder(pk, root(1), Slot::new(9), detected_at),
            BanOutcome::New
        );
        let always = |_: &BanEntry| true;
        assert!(cb.is_banned_with(&pk, detected_at, always));
        assert!(cb.is_banned_with(&pk, detected_at + 31, always));
        assert!(!cb.is_banned_with(&pk, detected_at + 32, always));
        assert!(!cb.is_banned_with(&pubkey(2), detected_at, always));

        cb.prune(detected_at + 31);
        assert_eq!(cb.num_ban_entries(), 1);
        cb.prune(detected_at + 32);
        assert_eq!(cb.num_ban_entries(), 0);
    }

    #[test]
    fn ban_same_block_is_idempotent() {
        let cb = breaker(3, 8);
        let pk = pubkey(1);
        assert_eq!(
            cb.ban_builder(pk, root(1), Slot::new(9), Slot::new(10)),
            BanOutcome::New
        );
        assert_eq!(
            cb.ban_builder(pk, root(1), Slot::new(9), Slot::new(20)),
            BanOutcome::AlreadyRecorded
        );
        assert_eq!(cb.num_ban_entries(), 1);
        // The original expiry is untouched.
        assert!(!cb.is_banned_with(&pk, Slot::new(42), |_| true));
    }

    #[test]
    fn second_offence_adds_entry_without_touching_first() {
        let cb = breaker(3, 8);
        let pk = pubkey(1);
        cb.ban_builder(pk, root(1), Slot::new(9), Slot::new(10)); // expires 42
        cb.ban_builder(pk, root(2), Slot::new(19), Slot::new(20)); // expires 52
        assert_eq!(cb.num_ban_entries(), 2);

        let only_first = |e: &BanEntry| e.block_root == root(1);
        let only_second = |e: &BanEntry| e.block_root == root(2);
        // At slot 45 the first entry has expired; only the second still bans.
        assert!(!cb.is_banned_with(&pk, Slot::new(45), only_first));
        assert!(cb.is_banned_with(&pk, Slot::new(45), only_second));
        // Before 42 either entry bans on its own chain.
        assert!(cb.is_banned_with(&pk, Slot::new(30), only_first));
        assert!(cb.is_banned_with(&pk, Slot::new(30), only_second));
        // A chain containing neither offending block is not affected.
        assert!(!cb.is_banned_with(&pk, Slot::new(30), |_| false));

        cb.prune(Slot::new(42));
        assert_eq!(cb.num_ban_entries(), 1);
    }

    #[test]
    fn is_banned_uses_state_block_roots_for_canonicity() {
        let cb = breaker(3, 8);
        let pk = pubkey(1);
        let state = state_with_history(&[Some(true), Some(false), None, Some(false)]);
        // Block roots: slot 2 => root(3), slot 4 => root(5).
        let offending_root = *state.get_block_root(Slot::new(2)).unwrap();
        cb.ban_builder(pk, offending_root, Slot::new(2), Slot::new(3));

        assert!(cb.is_banned(&pk, &state, state.slot()));

        // A fork where slot 2 holds a different block: the ban does not apply.
        let other_chain = state_with_history(&[Some(true), Some(true), None, Some(false)]);
        let mut other_chain = other_chain;
        other_chain
            .set_block_root(Slot::new(2), root(0xee))
            .unwrap();
        assert!(!cb.is_banned(&pk, &other_chain, other_chain.slot()));
    }

    #[test]
    fn is_banned_disabled() {
        let cb = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            disable_checks: true,
            ..config(3, 8)
        });
        let pk = pubkey(1);
        cb.ban_builder(pk, root(1), Slot::new(9), Slot::new(10));
        assert!(!cb.is_banned_with(&pk, Slot::new(10), |_| true));
    }

    // --- reveal decision ---------------------------------------------------------------------

    #[test]
    fn builder_payment_quorum_matches_spec() {
        let spec = E::default_spec();
        // 32 validators * 32 ETH.
        let total = 32 * 32_000_000_000u64;
        assert_eq!(
            builder_payment_quorum::<E>(total, &spec),
            Some(total / SPE * 6 / 10)
        );
        assert_eq!(builder_payment_quorum::<E>(0, &spec), Some(0));
        let mut zero_denominator = spec.clone();
        zero_denominator.builder_payment_threshold_denominator = 0;
        assert_eq!(builder_payment_quorum::<E>(total, &zero_denominator), None);
        let mut overflow = spec;
        overflow.builder_payment_threshold_numerator = u64::MAX;
        assert_eq!(builder_payment_quorum::<E>(u64::MAX, &overflow), None);
    }

    #[test]
    fn should_ban_truth_table() {
        let quorum = 100;
        assert!(should_ban_for_missed_reveal(
            7,
            false,
            false,
            Some(100),
            quorum
        ));
        assert!(should_ban_for_missed_reveal(
            7,
            false,
            false,
            Some(150),
            quorum
        ));
        // Not enough weight.
        assert!(!should_ban_for_missed_reveal(
            7,
            false,
            false,
            Some(99),
            quorum
        ));
        assert!(!should_ban_for_missed_reveal(7, false, false, None, quorum));
        // Payload was received.
        assert!(!should_ban_for_missed_reveal(
            7,
            true,
            false,
            Some(150),
            quorum
        ));
        // PTC saw it even though we did not.
        assert!(!should_ban_for_missed_reveal(
            7,
            false,
            true,
            Some(150),
            quorum
        ));
        // Self-build is never a builder offence.
        assert!(!should_ban_for_missed_reveal(
            BUILDER_INDEX_SELF_BUILD,
            false,
            false,
            Some(150),
            quorum
        ));
    }
}
