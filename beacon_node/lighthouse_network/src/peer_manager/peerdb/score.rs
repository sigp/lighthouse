//! This contains the scoring logic for peers.
//!
//! A peer's score is a rational number in the range [-100, 100].
//!
//! As the logic develops this documentation will advance.
//!
//! The scoring algorithms are currently experimental.
use crate::behaviour::gossipsub_scoring_parameters::GREYLIST_THRESHOLD as GOSSIPSUB_GREYLIST_THRESHOLD;
use serde::Serialize;
use std::time::Instant;
use strum::AsRefStr;
use tokio::time::Duration;

lazy_static! {
    static ref HALFLIFE_DECAY: f64 = -(2.0f64.ln()) / SCORE_HALFLIFE;
}

/// The default score for new peers.
pub(crate) const DEFAULT_SCORE: f64 = 0.0;
/// The minimum reputation before a peer is disconnected.
const MIN_SCORE_BEFORE_DISCONNECT: f64 = -20.0;
/// The minimum reputation before a peer is banned.
const MIN_SCORE_BEFORE_BAN: f64 = -50.0;
/// If a peer has a lighthouse score below this constant all other score parts will get ignored and
/// the peer will get banned regardless of the other parts.
const MIN_LIGHTHOUSE_SCORE_BEFORE_BAN: f64 = -60.0;
/// The maximum score a peer can obtain.
const MAX_SCORE: f64 = 100.0;
/// The minimum score a peer can obtain.
const MIN_SCORE: f64 = -100.0;
/// The halflife of a peer's score. I.e the number of seconds it takes for the score to decay to half its value.
const SCORE_HALFLIFE: f64 = 600.0;
/// The number of seconds we ban a peer for before their score begins to decay.
const BANNED_BEFORE_DECAY: Duration = Duration::from_secs(12 * 3600); // 12 hours

/// We weight negative gossipsub scores in such a way that they never result in a disconnect by
/// themselves. This "solves" the problem of non-decaying gossipsub scores for disconnected peers.
const GOSSIPSUB_NEGATIVE_SCORE_WEIGHT: f64 =
    (MIN_SCORE_BEFORE_DISCONNECT + 1.0) / GOSSIPSUB_GREYLIST_THRESHOLD;
const GOSSIPSUB_POSITIVE_SCORE_WEIGHT: f64 = GOSSIPSUB_NEGATIVE_SCORE_WEIGHT;

/// A collection of actions a peer can perform which will adjust its score.
/// Each variant has an associated score change.
// To easily assess the behaviour of scores changes the number of variants should stay low, and
// somewhat generic.
#[derive(Debug, Clone, Copy, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum PeerAction {
    /// We should not communicate more with this peer.
    /// This action will cause the peer to get banned.
    Fatal,
    /// This peer's action is not malicious but will not be tolerated. A few occurrences will cause
    /// the peer to get kicked.
    /// NOTE: ~5 occurrences will get the peer banned
    LowToleranceError,
    /// An error occurred with this peer but it is not necessarily malicious.
    /// We have high tolerance for this actions: several occurrences are needed for a peer to get
    /// kicked.
    /// NOTE: ~10 occurrences will get the peer banned
    MidToleranceError,
    /// An error occurred with this peer but it is not necessarily malicious.
    /// We have high tolerance for this actions: several occurrences are needed for a peer to get
    /// kicked.
    /// NOTE: ~50 occurrences will get the peer banned
    HighToleranceError,
}

/// Service reporting a `PeerAction` for a peer.
#[derive(Debug)]
pub enum ReportSource {
    Gossipsub,
    RPC,
    Processor,
    SyncService,
    PeerManager,
}

impl From<ReportSource> for &'static str {
    fn from(report_source: ReportSource) -> &'static str {
        match report_source {
            ReportSource::Gossipsub => "gossipsub",
            ReportSource::RPC => "rpc_error",
            ReportSource::Processor => "processor",
            ReportSource::SyncService => "sync",
            ReportSource::PeerManager => "peer_manager",
        }
    }
}

impl std::fmt::Display for PeerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAction::Fatal => write!(f, "Fatal"),
            PeerAction::LowToleranceError => write!(f, "Low Tolerance Error"),
            PeerAction::MidToleranceError => write!(f, "Mid Tolerance Error"),
            PeerAction::HighToleranceError => write!(f, "High Tolerance Error"),
        }
    }
}

/// The expected state of the peer given the peer's score.
#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum ScoreState {
    /// We are content with the peers performance. We permit connections and messages.
    Healthy,
    /// The peer should be disconnected. We allow re-connections if the peer is persistent.
    Disconnected,
    /// The peer is banned. We disallow new connections until it's score has decayed into a
    /// tolerable threshold.
    Banned,
}

impl std::fmt::Display for ScoreState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreState::Healthy => write!(f, "Healthy"),
            ScoreState::Banned => write!(f, "Banned"),
            ScoreState::Disconnected => write!(f, "Disconnected"),
        }
    }
}

/// A peer's score (perceived potential usefulness).
///
/// This simplistic version consists of a global score per peer which decays to 0 over time. The
/// decay rate applies equally to positive and negative scores.
#[derive(PartialEq, Clone, Debug, Serialize)]
pub struct RealScore {
    /// The global score.
    // NOTE: In the future we may separate this into sub-scores involving the RPC, Gossipsub and
    // lighthouse.
    lighthouse_score: f64,
    gossipsub_score: f64,
    /// We ignore the negative gossipsub scores of some peers to allow decaying without
    /// disconnecting.
    ignore_negative_gossipsub_score: bool,
    score: f64,
    /// The time the score was last updated to perform time-based adjustments such as score-decay.
    #[serde(skip)]
    last_updated: Instant,
}

impl Default for RealScore {
    fn default() -> Self {
        RealScore {
            lighthouse_score: DEFAULT_SCORE,
            gossipsub_score: DEFAULT_SCORE,
            score: DEFAULT_SCORE,
            last_updated: Instant::now(),
            ignore_negative_gossipsub_score: false,
        }
    }
}

impl RealScore {
    /// Access to the underlying score.
    fn recompute_score(&mut self) {
        self.score = self.lighthouse_score;
        if self.lighthouse_score <= MIN_LIGHTHOUSE_SCORE_BEFORE_BAN {
            //ignore all other scores, i.e. do nothing here
        } else if self.gossipsub_score >= 0.0 {
            self.score += self.gossipsub_score * GOSSIPSUB_POSITIVE_SCORE_WEIGHT;
        } else if !self.ignore_negative_gossipsub_score {
            self.score += self.gossipsub_score * GOSSIPSUB_NEGATIVE_SCORE_WEIGHT;
        }
    }

    fn score(&self) -> f64 {
        self.score
    }

    /// Modifies the score based on a peer's action.
    pub fn apply_peer_action(&mut self, peer_action: PeerAction) {
        match peer_action {
            PeerAction::Fatal => self.set_lighthouse_score(MIN_SCORE), // The worst possible score
            PeerAction::LowToleranceError => self.add(-10.0),
            PeerAction::MidToleranceError => self.add(-5.0),
            PeerAction::HighToleranceError => self.add(-1.0),
        }
    }

    fn set_lighthouse_score(&mut self, new_score: f64) {
        self.lighthouse_score = new_score;
        self.update_state();
    }

    /// Add an f64 to the score abiding by the limits.
    fn add(&mut self, score: f64) {
        let mut new_score = self.lighthouse_score + score;
        if new_score > MAX_SCORE {
            new_score = MAX_SCORE;
        }
        if new_score < MIN_SCORE {
            new_score = MIN_SCORE;
        }

        self.set_lighthouse_score(new_score);
    }

    fn update_state(&mut self) {
        let was_not_banned = self.score > MIN_SCORE_BEFORE_BAN;
        self.recompute_score();
        if was_not_banned && self.score <= MIN_SCORE_BEFORE_BAN {
            //we ban this peer for at least BANNED_BEFORE_DECAY seconds
            self.last_updated += BANNED_BEFORE_DECAY;
        }
    }

    /// Add an f64 to the score abiding by the limits.
    #[cfg(test)]
    pub fn test_add(&mut self, score: f64) {
        self.add(score);
    }

    #[cfg(test)]
    // reset the score
    pub fn test_reset(&mut self) {
        self.set_lighthouse_score(0f64);
    }

    // Set the gossipsub_score to a specific f64.
    // Used in testing to induce score status changes during a heartbeat.
    #[cfg(test)]
    pub fn set_gossipsub_score(&mut self, score: f64) {
        self.gossipsub_score = score;
    }

    /// Applies time-based logic such as decay rates to the score.
    /// This function should be called periodically.
    pub fn update(&mut self) {
        self.update_at(Instant::now())
    }

    /// Applies time-based logic such as decay rates to the score with the given now value.
    /// This private sub function is mainly used for testing.
    fn update_at(&mut self, now: Instant) {
        // Decay the current score
        // Using exponential decay based on a constant half life.

        // It is important that we use here `checked_duration_since` instead of elapsed, since
        // we set last_updated to the future when banning peers. Therefore `checked_duration_since`
        // will return None in this case and the score does not get decayed.
        if let Some(secs_since_update) = now
            .checked_duration_since(self.last_updated)
            .map(|d| d.as_secs())
        {
            // e^(-ln(2)/HL*t)
            let decay_factor = (*HALFLIFE_DECAY * secs_since_update as f64).exp();
            self.lighthouse_score *= decay_factor;
            self.last_updated = now;
            self.update_state();
        }
    }

    pub fn update_gossipsub_score(&mut self, new_score: f64, ignore: bool) {
        // we only update gossipsub if last_updated is in the past which means either the peer is
        // not banned or the BANNED_BEFORE_DECAY time is over.
        if self.last_updated <= Instant::now() {
            self.gossipsub_score = new_score;
            self.ignore_negative_gossipsub_score = ignore;
            self.update_state();
        }
    }

    pub fn is_good_gossipsub_peer(&self) -> bool {
        self.gossipsub_score >= 0.0
    }
}

#[derive(PartialEq, Clone, Debug, Serialize)]
pub enum Score {
    Max,
    Real(RealScore),
}

impl Default for Score {
    fn default() -> Self {
        Self::Real(RealScore::default())
    }
}

macro_rules! apply {
    ( $method:ident $(, $param_name: ident: $param_type: ty)*) => {
        impl Score {
            pub fn $method(
                &mut self, $($param_name: $param_type, )*
            ) {
                if let Self::Real(score) = self {
                    score.$method($($param_name, )*);
                }
            }
        }
    };
}

apply!(apply_peer_action, peer_action: PeerAction);
apply!(update);
apply!(update_gossipsub_score, new_score: f64, ignore: bool);
#[cfg(test)]
apply!(test_add, score: f64);
#[cfg(test)]
apply!(test_reset);
#[cfg(test)]
apply!(set_gossipsub_score, score: f64);

impl Score {
    pub fn score(&self) -> f64 {
        match self {
            Self::Max => f64::INFINITY,
            Self::Real(score) => score.score(),
        }
    }

    pub fn max_score() -> Self {
        Self::Max
    }

    /// Returns the expected state of the peer given it's score.
    pub(crate) fn state(&self) -> ScoreState {
        match self.score() {
            x if x <= MIN_SCORE_BEFORE_BAN => ScoreState::Banned,
            x if x <= MIN_SCORE_BEFORE_DISCONNECT => ScoreState::Disconnected,
            _ => ScoreState::Healthy,
        }
    }

    pub fn is_good_gossipsub_peer(&self) -> bool {
        match self {
            Self::Max => true,
            Self::Real(score) => score.is_good_gossipsub_peer(),
        }
    }
}

impl Eq for Score {}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Score) -> Option<std::cmp::Ordering> {
        self.score().partial_cmp(&other.score())
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Score) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl std::fmt::Display for Score {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2}", self.score())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_reputation_change() {
        let mut score = Score::default();

        // 0 change does not change de reputation
        //
        let change = 0.0;
        score.test_add(change);
        assert_eq!(score.score(), DEFAULT_SCORE);

        // underflowing change is capped
        let mut score = Score::default();
        let change = MIN_SCORE - 50.0;
        score.test_add(change);
        assert_eq!(score.score(), MIN_SCORE);

        // overflowing change is capped
        let mut score = Score::default();
        let change = MAX_SCORE + 50.0;
        score.test_add(change);
        assert_eq!(score.score(), MAX_SCORE);

        // Score adjusts
        let mut score = Score::default();
        let change = 1.32;
        score.test_add(change);
        assert_eq!(score.score(), DEFAULT_SCORE + change);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_ban_time() {
        let mut score = RealScore::default();
        let now = Instant::now();

        let change = MIN_SCORE_BEFORE_BAN;
        score.test_add(change);
        assert_eq!(score.score(), MIN_SCORE_BEFORE_BAN);

        score.update_at(now + BANNED_BEFORE_DECAY);
        assert_eq!(score.score(), MIN_SCORE_BEFORE_BAN);

        score.update_at(now + BANNED_BEFORE_DECAY + Duration::from_secs(1));
        assert!(score.score() > MIN_SCORE_BEFORE_BAN);
    }

    #[test]
    fn test_very_negative_gossipsub_score() {
        let mut score = Score::default();
        score.update_gossipsub_score(GOSSIPSUB_GREYLIST_THRESHOLD, false);
        assert!(!score.is_good_gossipsub_peer());
        assert!(score.score() < 0.0);
        assert_eq!(score.state(), ScoreState::Healthy);
        score.test_add(-1.0001);
        assert_eq!(score.state(), ScoreState::Disconnected);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_ignored_gossipsub_score() {
        let mut score = Score::default();
        score.update_gossipsub_score(GOSSIPSUB_GREYLIST_THRESHOLD, true);
        assert!(!score.is_good_gossipsub_peer());
        assert_eq!(score.score(), 0.0);
    }
}
