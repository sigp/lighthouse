//! The post-Gloas builder circuit breaker.
//!
//! After Gloas (ePBS) a proposer commits to a builder's *bid* and the builder is expected to
//! reveal the corresponding execution payload later in the slot. Builder failures therefore show
//! up as beacon blocks whose payloads never land, not as missed slots. This module decides when
//! external bids should be ignored in favour of the local build:
//!
//! - **Skip rules**: too many missed payloads in a row, or too many in the last `SLOTS_PER_EPOCH`
//!   slots, on the chain being extended. A "missed payload" is a slot that has a beacon block
//!   whose execution payload was never applied, even though the block reached the builder payment
//!   quorum for a bid of non-zero value. Below the quorum the builder is not charged and may
//!   honestly withhold (e.g. after a late block), and self-builds bid zero, so neither is counted.
//!   Slots with no beacon block at all are a validator or network failure and are not counted.
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
use safe_arith::ArithError;
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
    /// FULL, and with its total active balance cache built. Returns `None` without touching the
    /// state when checks are disabled.
    ///
    /// `previous_slot_reached_quorum` is fork choice's verdict on whether the block proposed at
    /// `produce_at_slot - 1` (if any) reached the builder payment quorum. See [`MissCriteria`].
    pub fn evaluate_skips_for_state<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        produce_at_slot: Slot,
        previous_slot_reached_quorum: bool,
        spec: &ChainSpec,
    ) -> Result<Option<FailedCondition>, BeaconStateError> {
        if self.config.disable_checks {
            return Ok(None);
        }
        if state.slot() != produce_at_slot {
            return Err(BeaconStateError::SlotOutOfBounds);
        }
        let quorum = builder_payment_quorum::<E>(state.get_total_active_balance()?, spec)
            .ok_or(BeaconStateError::ArithError(ArithError::Overflow))?;
        let criteria = MissCriteria {
            produce_at_slot,
            quorum,
            previous_slot_reached_quorum,
        };
        let consecutive_missed =
            count_consecutive_missed_payloads(state, &criteria, self.config.skips)?;
        let window_missed = count_missed_payloads_in_window(state, &criteria)?;
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

/// What makes a [`SlotStatus::PayloadMissing`] slot count towards the skip rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissCriteria {
    /// The slot being proposed in, which the state is advanced to.
    pub produce_at_slot: Slot,
    /// The builder payment quorum, see [`builder_payment_quorum`].
    pub quorum: u64,
    /// Fork choice's verdict on the block proposed at `produce_at_slot - 1`. No later block has
    /// included that slot's attestations, so its on-chain payment weight is still zero.
    ///
    /// Only meaningful for that one slot: fork choice's weight for an older block also includes
    /// votes cast in later slots, which the payment weight does not.
    pub previous_slot_reached_quorum: bool,
}

/// Whether the builder of the block at `slot` is charged for it, which obliges it to reveal: the
/// bid has a non-zero value and the block reached the builder payment quorum.
///
/// Read from `state.builder_pending_payments`, where a payment stays until its payload lands or
/// its epoch is settled. Always `false` for a self-build (zero value), for a block whose proposer
/// was slashed for it, and for slots before the previous epoch, whose payments are gone.
///
/// The weight only includes attestations that later blocks have included, so it can under-report
/// a block that is followed by empty slots.
fn builder_is_charged<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    criteria: &MissCriteria,
) -> Result<bool, BeaconStateError> {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let slot_in_epoch = slot.as_usize() % slots_per_epoch;
    let epoch = slot.epoch(E::slots_per_epoch());
    let payment_index = if epoch == state.current_epoch() {
        slots_per_epoch.saturating_add(slot_in_epoch)
    } else if epoch.saturating_add(1u64) == state.current_epoch() {
        slot_in_epoch
    } else {
        return Ok(false);
    };
    let payment = state.builder_pending_payments()?.get(payment_index).ok_or(
        BeaconStateError::InvalidBuilderPendingPaymentsIndex(payment_index),
    )?;

    let reached_quorum = payment.weight >= criteria.quorum
        || (criteria.previous_slot_reached_quorum
            && slot.saturating_add(1u64) == criteria.produce_at_slot);
    Ok(payment.withdrawal.amount > 0 && reached_quorum)
}

/// Count how many blocks in a row, walking back from `produce_at_slot - 1`, had a missed payload
/// that its builder is charged for.
///
/// Slots with no block, and missed payloads the builder is not charged for, are skipped over: they
/// are neither a failure nor a success. The walk stops at the first block whose payload landed,
/// once the count exceeds `limit`, or at the start of the previous epoch, before which the state
/// holds no builder payments.
pub fn count_consecutive_missed_payloads<E: EthSpec>(
    state: &BeaconState<E>,
    criteria: &MissCriteria,
    limit: usize,
) -> Result<usize, BeaconStateError> {
    let earliest_slot = state.previous_epoch().start_slot(E::slots_per_epoch());
    let mut count = 0;
    for slot in (earliest_slot.as_u64()..criteria.produce_at_slot.as_u64()).rev() {
        let slot = Slot::new(slot);
        match slot_status(state, slot)? {
            SlotStatus::PayloadPresent => break,
            SlotStatus::PayloadMissing if builder_is_charged(state, slot, criteria)? => {
                count += 1;
                if count > limit {
                    break;
                }
            }
            SlotStatus::NoBlock | SlotStatus::PayloadMissing => continue,
        }
    }
    Ok(count)
}

/// Count missed payloads that their builder is charged for in the `SLOTS_PER_EPOCH` slots before
/// `produce_at_slot`.
pub fn count_missed_payloads_in_window<E: EthSpec>(
    state: &BeaconState<E>,
    criteria: &MissCriteria,
) -> Result<usize, BeaconStateError> {
    let produce_at_slot = criteria.produce_at_slot;
    let window_start = produce_at_slot.saturating_sub(E::slots_per_epoch());
    let mut count = 0;
    for slot in window_start.as_u64()..produce_at_slot.as_u64() {
        let slot = Slot::new(slot);
        if slot_status(state, slot)? == SlotStatus::PayloadMissing
            && builder_is_charged(state, slot, criteria)?
        {
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
/// payload was healthy, and enough attestation weight on the block that the builder is charged
/// for it.
///
/// The PTC excuse requires *both* a timely-reveal majority and a data-available majority — the
/// same conjunction fork choice's `should_extend_payload` uses. A payload revealed on time whose
/// blob data was withheld (timely but not available) is still a builder offence: the slot goes
/// empty and the builder is charged, exactly as if the envelope had never been revealed.
pub fn should_ban_for_missed_reveal(
    builder_index: BuilderIndex,
    payload_received: bool,
    ptc_votes_timely: bool,
    ptc_votes_data_available: bool,
    block_weight: Option<u64>,
    quorum: u64,
) -> bool {
    builder_index != BUILDER_INDEX_SELF_BUILD
        && !payload_received
        && !(ptc_votes_timely && ptc_votes_data_available)
        && block_weight.is_some_and(|weight| weight >= quorum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use types::{
        BuilderPendingPayment, BuilderPendingWithdrawal, Epoch, ExecutionBlockHash,
        ExecutionPayloadHeader, ExecutionPayloadHeaderFulu, ForkName, MinimalEthSpec,
    };

    type E = MinimalEthSpec;
    const SPE: u64 = 8; // MinimalEthSpec::slots_per_epoch()
    /// A payment weight above any quorum a 64-validator state can produce.
    const CHARGED: u64 = u64::MAX;

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

    fn gloas_spec() -> ChainSpec {
        ForkName::Gloas.make_genesis_spec(E::default_spec())
    }

    fn gloas_genesis_state() -> (BeaconState<E>, ChainSpec) {
        let spec = gloas_spec();
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
    ///
    /// Every block carries a non-zero bid whose payment weight is [`CHARGED`], so its builder is
    /// charged for it; use [`set_payment`] to change that for individual slots.
    fn state_with_history(history: &[Option<bool>]) -> BeaconState<E> {
        let (mut state, spec) = gloas_genesis_state();
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
                set_payment(&mut state, s, 1, CHARGED);
            }
            state.set_block_root(s, latest_root).unwrap();
        }
        state.build_total_active_balance_cache(&spec).unwrap();
        state
    }

    /// Set the pending payment for the block at `slot`, if the state still holds its epoch.
    fn set_payment(state: &mut BeaconState<E>, slot: Slot, amount: u64, weight: u64) {
        let epoch = slot.epoch(SPE);
        let slot_in_epoch = (slot.as_u64() % SPE) as usize;
        let index = if epoch == state.current_epoch() {
            SPE as usize + slot_in_epoch
        } else if epoch + 1 == state.current_epoch() {
            slot_in_epoch
        } else {
            return;
        };
        *state
            .builder_pending_payments_mut()
            .unwrap()
            .get_mut(index)
            .unwrap() = BuilderPendingPayment {
            weight,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: Default::default(),
                amount,
                builder_index: 1,
            },
            proposer_index: 0,
        };
    }

    /// Criteria for a proposal at the state's slot: any non-zero weight reaches the quorum and
    /// fork choice has no verdict on the previous slot.
    fn criteria(state: &BeaconState<E>) -> MissCriteria {
        MissCriteria {
            produce_at_slot: state.slot(),
            quorum: 1,
            previous_slot_reached_quorum: false,
        }
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
        let criteria = criteria(&state);
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria, 100).unwrap(),
            3
        );
        // Stops early once the limit is exceeded.
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria, 1).unwrap(),
            2
        );
    }

    #[test]
    fn consecutive_missed_is_zero_when_latest_payload_present() {
        let state = state_with_history(&[Some(false), Some(false), None, Some(true)]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria(&state), 100).unwrap(),
            0
        );
    }

    #[test]
    fn consecutive_missed_ignores_empty_slots_entirely() {
        // Only empty slots after the last present payload: not a builder failure.
        let state = state_with_history(&[Some(true), None, None, None, None]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria(&state), 100).unwrap(),
            0
        );
    }

    #[test]
    fn consecutive_missed_walks_back_to_genesis() {
        // Every block since genesis missed its payload; genesis itself counts as present.
        let state = state_with_history(&[Some(false), Some(false)]);
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria(&state), 100).unwrap(),
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
        assert_eq!(state.slot(), Slot::new(13));
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria(&state)).unwrap(),
            3
        );
    }

    #[test]
    fn window_saturates_at_genesis() {
        let state = state_with_history(&[Some(false), Some(false)]);
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria(&state)).unwrap(),
            2
        );
    }

    #[test]
    fn uncharged_misses_are_neutral() {
        // slots 1..=5: present, missing, missing, missing, missing; slot 3 is below the quorum.
        let mut state = state_with_history(&[
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        ]);
        set_payment(&mut state, Slot::new(3), 1, 0);
        let criteria = criteria(&state);
        // Skipped over like an empty slot: it neither counts nor ends the run.
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria, 100).unwrap(),
            3
        );
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria).unwrap(),
            3
        );
    }

    #[test]
    fn zero_value_misses_are_not_counted() {
        // A self-build (or any zero-value bid) never reaches the quorum, whatever its weight.
        let mut state = state_with_history(&[Some(true), Some(false), Some(false)]);
        set_payment(&mut state, Slot::new(2), 0, CHARGED);
        let criteria = criteria(&state);
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria, 100).unwrap(),
            1
        );
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria).unwrap(),
            1
        );
    }

    #[test]
    fn previous_slot_takes_fork_choice_verdict() {
        // Neither block has any attestation weight on chain yet.
        let mut state = state_with_history(&[Some(true), Some(false), Some(false)]);
        set_payment(&mut state, Slot::new(2), 1, 0);
        set_payment(&mut state, Slot::new(3), 1, 0);
        let mut criteria = criteria(&state);
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria).unwrap(),
            0
        );
        // The verdict only ever applies to the slot before the proposal.
        criteria.previous_slot_reached_quorum = true;
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria, 100).unwrap(),
            1
        );
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria).unwrap(),
            1
        );
        // A zero-value bid in the previous slot is still not counted.
        set_payment(&mut state, Slot::new(3), 0, 0);
        assert_eq!(
            count_missed_payloads_in_window(&state, &criteria).unwrap(),
            0
        );
    }

    #[test]
    fn consecutive_missed_stops_at_previous_epoch() {
        // Every block in slots 1..=17 missed its payload. The state is at slot 18 (epoch 2) and
        // holds payments for epochs 1 and 2 only, so the walk stops at slot 8.
        let history = vec![Some(false); 17];
        let state = state_with_history(&history);
        assert_eq!(state.current_epoch(), Epoch::new(2));
        assert_eq!(
            count_consecutive_missed_payloads(&state, &criteria(&state), 100).unwrap(),
            10
        );
    }

    #[test]
    fn evaluate_skips_for_state_end_to_end() {
        let state = state_with_history(&[Some(true), Some(false), None, Some(false), Some(false)]);
        let slot = state.slot();
        let spec = gloas_spec();
        // 3 in a row, 4 in the window.
        assert_eq!(
            breaker(3, 8)
                .evaluate_skips_for_state(&state, slot, false, &spec)
                .unwrap(),
            None
        );
        assert_eq!(
            breaker(2, 8)
                .evaluate_skips_for_state(&state, slot, false, &spec)
                .unwrap(),
            Some(FailedCondition::Skips)
        );
        assert_eq!(
            breaker(3, 2)
                .evaluate_skips_for_state(&state, slot, false, &spec)
                .unwrap(),
            Some(FailedCondition::SkipsPerEpoch)
        );
        // Wrong slot is rejected.
        assert!(
            breaker(3, 8)
                .evaluate_skips_for_state(&state, slot + 1, false, &spec)
                .is_err()
        );
        // Disabled checks never read the state.
        let disabled = CircuitBreaker::new::<E>(CircuitBreakerConfig {
            disable_checks: true,
            ..config(0, 0)
        });
        assert_eq!(
            disabled
                .evaluate_skips_for_state(&state, slot + 1, false, &spec)
                .unwrap(),
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
            false,
            Some(100),
            quorum
        ));
        assert!(should_ban_for_missed_reveal(
            7,
            false,
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
            false,
            Some(99),
            quorum
        ));
        assert!(!should_ban_for_missed_reveal(
            7, false, false, false, None, quorum
        ));
        // Payload was received.
        assert!(!should_ban_for_missed_reveal(
            7,
            true,
            false,
            false,
            Some(150),
            quorum
        ));
        // PTC saw a timely payload with available data even though we did not.
        assert!(!should_ban_for_missed_reveal(
            7,
            false,
            true,
            true,
            Some(150),
            quorum
        ));
        // A timely reveal does not excuse withheld blob data.
        assert!(should_ban_for_missed_reveal(
            7,
            false,
            true,
            false,
            Some(150),
            quorum
        ));
        // Available data does not excuse a late reveal.
        assert!(should_ban_for_missed_reveal(
            7,
            false,
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
            false,
            Some(150),
            quorum
        ));
    }
}
