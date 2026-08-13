//! Fork-agnostic ePBS payload-bid selection.
//!
//! Given the candidate bids for a slot, pick the winner. Selection is **value-based**: it never
//! inspects payload contents, only each candidate's ranking key.
//!
//! Every candidate — the local self-build and each external bid — is one [`BidCandidate`], tagged by
//! its [`BidSource`]. The source is the single home for per-source data: `Local` carries the
//! [`ExecutionPayloadData`] needed to build the envelope plus its EL block value, `Direct` carries
//! the builder URL (to route the winning block back via `Eth-Builder-Url`) plus the proposer's
//! `max_execution_payment` cap, and `Gossip` carries nothing. There is no separate "winning bid"
//! type — the winner *is* a [`BidCandidate`], and the caller matches on its `source`.
//!
//! All value math lives on [`BidCandidate`] and is computed on demand — nothing is precomputed. A
//! candidate's ranking key is its trusted value (the local block value, or a bid's clamped value)
//! scaled by `builder_boost_factor`, all in wei so the local EL block value compares directly. The
//! ordering is: the EL's `shouldOverrideBuilder`, then whether the bid clears its `min_bid` floor,
//! then the boosted value, then ties go to the local build, then to the earlier candidate. `min_bid`
//! is ranked, not filtered, so a below-floor bid is a last resort rather than a dropped one.
//!
//! Consumed by `gloas.rs` block production via [`select_payload_bid`].

use sensitive_url::SensitiveUrl;
use std::sync::Arc;
use types::{
    EthSpec, ExecutionPayloadGloas, ExecutionRequestsGloas, SignedExecutionPayloadBid, Slot,
    Uint256,
};

const GWEI_TO_WEI: u64 = 1_000_000_000;

/// The neutral `builder_boost_factor` (100% -> ×1). The local build competes at neutral boost.
const NEUTRAL_BOOST_FACTOR: u64 = 100;

/// Convert a gwei figure to wei. Saturating, though realistic values are nowhere near the ceiling.
fn gwei_to_wei(gwei: u64) -> Uint256 {
    Uint256::from(gwei).saturating_mul(Uint256::from(GWEI_TO_WEI))
}

/// Data needed to construct an `ExecutionPayloadEnvelope`, carried by the local candidate and
/// materialized only if it wins.
///
/// Fork-coupling seam: `payload`/`execution_requests` are concrete Gloas types. Selection never
/// inspects them.
pub struct ExecutionPayloadData<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequestsGloas<E>,
    pub builder_index: u64,
    pub slot: Slot,
    pub blobs_and_proofs: (types::BlobsList<E>, types::KzgProofs<E>),
}

/// Where a payload bid came from, and the per-source data the winner needs (plus each source's
/// ranking input).
pub enum BidSource<E: EthSpec> {
    /// The locally-built payload. Carries the envelope data (boxed to keep the enum small), the EL's
    /// `shouldOverrideBuilder` signal, and the EL block value (its ranking value, in wei).
    Local {
        payload_data: Box<ExecutionPayloadData<E>>,
        should_override_builder: bool,
        block_value: Uint256,
    },
    /// A bid from the `execution_payload_bid` gossip topic. Its `execution_payment` is zero, so there
    /// is nothing to clamp.
    Gossip,
    /// A bid fetched directly from a builder. Carries its URL (to route a winning block back via
    /// `submitSignedBeaconBlock` / `Eth-Builder-Url`) and the proposer's `max_execution_payment` cap
    /// for this builder.
    Direct {
        builder_url: SensitiveUrl,
        max_execution_payment: u64,
    },
}

/// A payload-bid candidate: the committed bid, the proposer's boost for it, and its [`BidSource`].
///
/// Everything derivable (trusted value, ranking key, reported value) is a method — nothing is stored
/// that could be recomputed from these fields.
pub struct BidCandidate<E: EthSpec> {
    pub signed_bid: Arc<SignedExecutionPayloadBid<E>>,
    /// The proposer's boost multiplier for this candidate; `100` (neutral) for the local build.
    builder_boost_factor: u64,
    /// The proposer's `min_bid` acceptance floor (gwei) for this candidate; `0` for the local build,
    /// which is the proposer's own block and is never gated.
    min_bid: u64,
    pub source: BidSource<E>,
}

impl<E: EthSpec> BidCandidate<E> {
    /// The local self-build candidate, competing at neutral boost. `block_value` is its EL block
    /// value (wei), used both to rank and to report.
    pub fn local(
        signed_bid: SignedExecutionPayloadBid<E>,
        payload_data: ExecutionPayloadData<E>,
        block_value: Uint256,
        should_override_builder: bool,
    ) -> Self {
        Self {
            signed_bid: Arc::new(signed_bid),
            builder_boost_factor: NEUTRAL_BOOST_FACTOR,
            min_bid: 0,
            source: BidSource::Local {
                payload_data: Box::new(payload_data),
                should_override_builder,
                block_value,
            },
        }
    }

    /// A gossip candidate under the global `builder_boost_factor` and `min_bid`.
    pub fn gossip(
        signed_bid: Arc<SignedExecutionPayloadBid<E>>,
        builder_boost_factor: u64,
        min_bid: u64,
    ) -> Self {
        Self {
            signed_bid,
            builder_boost_factor,
            min_bid,
            source: BidSource::Gossip,
        }
    }

    /// A direct-builder candidate under this builder's resolved policy.
    ///
    /// `max_execution_payment` is the largest `execution_payment` (gwei) the proposer trusts from this
    /// builder (`u64::MAX` = no clamp, `0` = untrusted); over-cap payment is clamped out of the
    /// ranking value but still reported. `builder_boost_factor`: `100` neutral, `0` prefers local,
    /// `u64::MAX` strongly favors the builder. Note it is a plain multiplier, not the pre-Gloas
    /// absolute "always prefer" override: a zero-value bid still ranks 0 (`0 × u64::MAX == 0`), so a
    /// non-zero local build outranks it. `min_bid` is the acceptance floor (gwei).
    pub fn direct(
        signed_bid: Arc<SignedExecutionPayloadBid<E>>,
        builder_boost_factor: u64,
        max_execution_payment: u64,
        min_bid: u64,
        builder_url: SensitiveUrl,
    ) -> Self {
        Self {
            signed_bid,
            builder_boost_factor,
            min_bid,
            source: BidSource::Direct {
                builder_url,
                max_execution_payment,
            },
        }
    }

    /// The trusted value ranking is based on, in **wei**: the local EL block value, or a bid's
    /// `value + min(execution_payment, max_execution_payment)`. Untrusted payment above the cap is
    /// excluded so it can't sway ranking.
    fn trusted_value(&self) -> Uint256 {
        let bid = &self.signed_bid.message;
        match &self.source {
            BidSource::Local { block_value, .. } => *block_value,
            BidSource::Gossip => gwei_to_wei(bid.value), // gossip `execution_payment` is zero
            BidSource::Direct {
                max_execution_payment,
                ..
            } => gwei_to_wei(
                bid.value
                    .saturating_add(bid.execution_payment.min(*max_execution_payment)),
            ),
        }
    }

    /// Lexicographic selection key (greater = better): `shouldOverrideBuilder`, then whether the bid
    /// clears its `min_bid` floor, then the boosted value (`trusted_value × builder_boost_factor`, in
    /// wei — `u64::MAX` multiplies through rather than acting as an absolute override, so a
    /// zero-value bid ranks 0 and loses to any non-zero local build), then the local build wins ties
    /// over externals.
    ///
    /// Ranking `min_bid` rather than filtering means a below-floor bid still wins when it's the only
    /// viable option — the local build failed and every bid is under the floor — instead of missing
    /// the slot. Whenever *any* candidate clears the floor (the local build always does), the
    /// below-floor ones lose regardless of value, exactly as a hard filter would.
    fn rank_key(&self) -> (bool, bool, Uint256, bool) {
        (
            self.overrides_builder(),
            self.meets_min_bid(),
            self.trusted_value()
                .saturating_mul(Uint256::from(self.builder_boost_factor)),
            self.is_local(),
        )
    }

    /// Whether the bid clears its `min_bid` floor: its trusted value is at least the floor. Untrusted
    /// payment (excluded from the trusted value) can't be used to clear it. Local is never gated
    /// (`min_bid` is `0`), so it always qualifies.
    fn meets_min_bid(&self) -> bool {
        self.trusted_value() >= gwei_to_wei(self.min_bid)
    }

    /// The wei value reported for the winner (`Eth-Execution-Payload-Value`): the local block value,
    /// or the **unclamped** `value + execution_payment` (the proposer's real revenue; the clamp is a
    /// ranking-only trust bound).
    pub fn payload_value(&self) -> Uint256 {
        let bid = &self.signed_bid.message;
        match &self.source {
            BidSource::Local { block_value, .. } => *block_value,
            _ => gwei_to_wei(bid.value.saturating_add(bid.execution_payment)),
        }
    }

    /// The winning builder's URL, if this bid came through the builder-API (direct) channel.
    ///
    /// Kept as a [`SensitiveUrl`] so it stays redacted in logs; the caller stringifies it only at
    /// the `Eth-Builder-Url` header boundary.
    pub fn builder_url(&self) -> Option<&SensitiveUrl> {
        match &self.source {
            BidSource::Direct { builder_url, .. } => Some(builder_url),
            _ => None,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self.source, BidSource::Local { .. })
    }

    fn overrides_builder(&self) -> bool {
        matches!(
            self.source,
            BidSource::Local {
                should_override_builder: true,
                ..
            }
        )
    }
}

/// Select the winning payload bid.
///
/// The total order is defined by [`rank_key`](BidCandidate::rank_key). On a full tie the earlier
/// candidate is kept. Returns `None` only when there are no candidates — the caller treats that as
/// block-production failure.
pub fn select_payload_bid<E: EthSpec>(candidates: Vec<BidCandidate<E>>) -> Option<BidCandidate<E>> {
    // `reduce` keeps `best` unless `candidate` is *strictly* greater, so the earliest of any tied
    // maxima wins.
    candidates.into_iter().reduce(|best, candidate| {
        if candidate.rank_key() > best.rank_key() {
            candidate
        } else {
            best
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;
    use ssz_types::VariableList;
    use types::{ExecutionPayloadBid, MainnetEthSpec};

    type TestSpec = MainnetEthSpec;

    const GOSSIP_BUILDER: u64 = 111;
    const DIRECT_BUILDER: u64 = 222;
    const LOCAL_BUILDER: u64 = 0;

    const NEUTRAL_BOOST: u64 = 100;
    const NO_CLAMP: u64 = u64::MAX;
    const DIRECT_URL: &str = "http://builder.example.com";

    fn gwei(n: u64) -> Uint256 {
        gwei_to_wei(n)
    }

    fn direct_url() -> SensitiveUrl {
        SensitiveUrl::parse(DIRECT_URL).expect("valid test url")
    }

    fn signed_bid(
        builder_index: u64,
        value_gwei: u64,
        payment_gwei: u64,
    ) -> Arc<SignedExecutionPayloadBid<TestSpec>> {
        Arc::new(SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                builder_index,
                value: value_gwei,
                execution_payment: payment_gwei,
                ..Default::default()
            },
            signature: Signature::empty(),
        })
    }

    fn gossip(value_gwei: u64, boost: u64) -> BidCandidate<TestSpec> {
        BidCandidate::gossip(signed_bid(GOSSIP_BUILDER, value_gwei, 0), boost, 0)
    }

    fn gossip_min_bid(value_gwei: u64, min_bid: u64) -> BidCandidate<TestSpec> {
        BidCandidate::gossip(
            signed_bid(GOSSIP_BUILDER, value_gwei, 0),
            NEUTRAL_BOOST,
            min_bid,
        )
    }

    fn direct(
        value_gwei: u64,
        payment_gwei: u64,
        boost: u64,
        max_payment: u64,
    ) -> BidCandidate<TestSpec> {
        BidCandidate::direct(
            signed_bid(DIRECT_BUILDER, value_gwei, payment_gwei),
            boost,
            max_payment,
            0,
            direct_url(),
        )
    }

    fn direct_min_bid(value_gwei: u64, max_payment: u64, min_bid: u64) -> BidCandidate<TestSpec> {
        BidCandidate::direct(
            signed_bid(DIRECT_BUILDER, value_gwei, 0),
            NEUTRAL_BOOST,
            max_payment,
            min_bid,
            direct_url(),
        )
    }

    fn local(block_value_gwei: u64, should_override_builder: bool) -> BidCandidate<TestSpec> {
        BidCandidate::local(
            SignedExecutionPayloadBid {
                message: ExecutionPayloadBid {
                    builder_index: LOCAL_BUILDER,
                    ..Default::default()
                },
                signature: Signature::empty(),
            },
            ExecutionPayloadData {
                payload: ExecutionPayloadGloas::default(),
                execution_requests: ExecutionRequestsGloas::default(),
                builder_index: LOCAL_BUILDER,
                slot: Slot::new(0),
                blobs_and_proofs: (VariableList::empty(), VariableList::empty()),
            },
            gwei(block_value_gwei),
            should_override_builder,
        )
    }

    /// `(winning_builder_index, is_local, payload_value_wei, source_label)`.
    fn outcome(win: BidCandidate<TestSpec>) -> (u64, bool, Uint256, &'static str) {
        let source = match &win.source {
            BidSource::Local { .. } => "local",
            BidSource::Gossip => "gossip",
            BidSource::Direct { .. } => "direct",
        };
        (
            win.signed_bid.message.builder_index,
            win.is_local(),
            win.payload_value(),
            source,
        )
    }

    #[test]
    fn local_only_wins() {
        let win = select_payload_bid(vec![local(7, false)]).unwrap();
        assert_eq!(outcome(win), (LOCAL_BUILDER, true, gwei(7), "local"));
    }

    #[test]
    fn external_only_wins_when_no_local() {
        let win = select_payload_bid(vec![gossip(5, NEUTRAL_BOOST)]).unwrap();
        assert_eq!(outcome(win), (GOSSIP_BUILDER, false, gwei(5), "gossip"));
    }

    #[test]
    fn nothing_viable_is_none() {
        assert!(select_payload_bid::<TestSpec>(vec![]).is_none());
    }

    #[test]
    fn el_override_beats_any_external() {
        let win = select_payload_bid(vec![local(1, true), direct(1000, 1000, u64::MAX, NO_CLAMP)])
            .unwrap();
        assert_eq!(outcome(win), (LOCAL_BUILDER, true, gwei(1), "local"));
    }

    #[test]
    fn local_wins_value_tie() {
        // Neutral boost, external trusted value == local block value ⇒ local wins ties.
        let win = select_payload_bid(vec![local(5, false), gossip(5, NEUTRAL_BOOST)]).unwrap();
        assert_eq!(outcome(win), (LOCAL_BUILDER, true, gwei(5), "local"));
    }

    #[test]
    fn external_wins_when_strictly_higher() {
        let win = select_payload_bid(vec![local(4, false), gossip(5, NEUTRAL_BOOST)]).unwrap();
        assert_eq!(outcome(win), (GOSSIP_BUILDER, false, gwei(5), "gossip"));
    }

    #[test]
    fn direct_bid_counts_execution_payment() {
        // value 2 + payment 4 = 6 ranked (neutral) ⇒ beats local 5, reported at 6.
        let win = select_payload_bid(vec![local(5, false), direct(2, 4, NEUTRAL_BOOST, NO_CLAMP)])
            .unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(6), "direct"));
    }

    #[test]
    fn max_execution_payment_clamps_ranking_but_not_reported_value() {
        // Unclamped: value 1 + payment 10 = 11 ranked (neutral) ⇒ beats local 5.
        let unclamped = select_payload_bid(vec![
            local(5, false),
            direct(1, 10, NEUTRAL_BOOST, NO_CLAMP),
        ])
        .unwrap();
        assert_eq!(
            outcome(unclamped),
            (DIRECT_BUILDER, false, gwei(11), "direct")
        );

        // Clamp payment to 3: ranked value = 1 + min(10, 3) = 4 < local 5 ⇒ local wins.
        let clamped =
            select_payload_bid(vec![local(5, false), direct(1, 10, NEUTRAL_BOOST, 3)]).unwrap();
        assert_eq!(outcome(clamped), (LOCAL_BUILDER, true, gwei(5), "local"));

        // Clamp still lets it win over local 3 (ranked 4 > 3) — but the *reported* value is the
        // unclamped proposer value 11, since the clamp is a ranking-only trust bound.
        let clamped_win =
            select_payload_bid(vec![local(3, false), direct(1, 10, NEUTRAL_BOOST, 3)]).unwrap();
        assert_eq!(
            outcome(clamped_win),
            (DIRECT_BUILDER, false, gwei(11), "direct")
        );
    }

    #[test]
    fn boost_amplifies_external() {
        // Ranked 3 < local 5 ⇒ local; boost 200 ⇒ ranked 6 > 5 ⇒ external wins, reported at 3.
        let no_boost = select_payload_bid(vec![local(5, false), gossip(3, NEUTRAL_BOOST)]).unwrap();
        assert_eq!(outcome(no_boost), (LOCAL_BUILDER, true, gwei(5), "local"));

        let boosted = select_payload_bid(vec![local(5, false), gossip(3, 200)]).unwrap();
        assert_eq!(outcome(boosted), (GOSSIP_BUILDER, false, gwei(3), "gossip"));
    }

    #[test]
    fn always_prefer_beats_higher_local() {
        // Local block value dwarfs the bid, but `u64::MAX` boost multiplies it past any realistic local.
        let win =
            select_payload_bid(vec![local(1000, false), direct(1, 0, u64::MAX, NO_CLAMP)]).unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(1), "direct"));
    }

    #[test]
    fn zero_value_always_prefer_loses_to_local() {
        // A zero-value always-prefer bid (0 × MAX = 0) correctly loses to a real local build.
        let win =
            select_payload_bid(vec![local(1, false), direct(0, 0, u64::MAX, NO_CLAMP)]).unwrap();
        assert_eq!(outcome(win), (LOCAL_BUILDER, true, gwei(1), "local"));
    }

    #[test]
    fn two_always_prefer_ranked_by_value() {
        let win = select_payload_bid(vec![
            direct(1, 0, u64::MAX, NO_CLAMP),
            direct(2, 0, u64::MAX, NO_CLAMP),
        ])
        .unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(2), "direct"));
    }

    #[test]
    fn ranks_highest_across_sources() {
        // Gossip ranked 10 (neutral) vs direct value 4 boosted 300 ⇒ ranked 12 ⇒ direct wins.
        let win = select_payload_bid(vec![gossip(10, NEUTRAL_BOOST), direct(4, 0, 300, NO_CLAMP)])
            .unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(4), "direct"));
    }

    #[test]
    fn direct_winner_carries_builder_url() {
        let win = select_payload_bid(vec![direct(5, 0, NEUTRAL_BOOST, NO_CLAMP)]).unwrap();
        assert_eq!(win.builder_url(), Some(&direct_url()));
    }

    #[test]
    fn below_min_bid_loses_to_local_regardless_of_value() {
        // Direct bids 20 but its floor is 100 ⇒ below floor ⇒ loses to the local build worth only 5.
        let win =
            select_payload_bid(vec![local(5, false), direct_min_bid(20, NO_CLAMP, 100)]).unwrap();
        assert_eq!(outcome(win), (LOCAL_BUILDER, true, gwei(5), "local"));
    }

    #[test]
    fn below_min_bid_wins_when_it_is_the_only_option() {
        // The local build failed and the only bid is under its floor ⇒ take it rather than miss the
        // slot (ranking `min_bid` rather than filtering).
        let win = select_payload_bid(vec![direct_min_bid(20, NO_CLAMP, 100)]).unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(20), "direct"));
    }

    #[test]
    fn floor_clearing_bid_beats_below_min_bid() {
        // A gossip bid of 6 clears its (zero) floor; a direct bid of 20 is under its floor 100 ⇒ the
        // floor-clearing bid wins despite its lower value.
        let win = select_payload_bid(vec![
            gossip(6, NEUTRAL_BOOST),
            direct_min_bid(20, NO_CLAMP, 100),
        ])
        .unwrap();
        assert_eq!(outcome(win), (GOSSIP_BUILDER, false, gwei(6), "gossip"));
    }

    #[test]
    fn min_bid_floor_uses_trusted_value() {
        // Value 4 + payment 10 but cap 0 ⇒ trusted value 4, below the floor 5; the unclamped value 14
        // can't clear it. It loses to a gossip bid of 1 that clears its own (zero) floor.
        let below = BidCandidate::direct(
            signed_bid(DIRECT_BUILDER, 4, 10),
            NEUTRAL_BOOST,
            0, // cap 0 ⇒ payment untrusted
            5, // min_bid floor
            direct_url(),
        );
        let win = select_payload_bid(vec![gossip(1, NEUTRAL_BOOST), below]).unwrap();
        assert_eq!(outcome(win), (GOSSIP_BUILDER, false, gwei(1), "gossip"));

        // The same bid still wins if it's the only option (its unclamped 14 is reported).
        let solo = BidCandidate::direct(
            signed_bid(DIRECT_BUILDER, 4, 10),
            NEUTRAL_BOOST,
            0,
            5,
            direct_url(),
        );
        assert_eq!(
            outcome(select_payload_bid(vec![solo]).unwrap()),
            (DIRECT_BUILDER, false, gwei(14), "direct")
        );
    }

    #[test]
    fn below_min_bid_gossip_loses_to_floor_clearing_direct() {
        // Gossip bids 4 under the global floor 5; a direct bid of only 1 clears its own floor ⇒ the
        // floor-clearing direct wins despite its lower value.
        let win = select_payload_bid(vec![
            gossip_min_bid(4, 5),
            direct(1, 0, NEUTRAL_BOOST, NO_CLAMP),
        ])
        .unwrap();
        assert_eq!(outcome(win), (DIRECT_BUILDER, false, gwei(1), "direct"));
    }
}
