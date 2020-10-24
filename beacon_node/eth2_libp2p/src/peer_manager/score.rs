//! This contains the scoring logic for peers.
//!
//! A peer's score is a rational number in the range [-100, 100].
//!
//! As the logic develops this documentation will advance.
//!
//! The scoring algorithms are currently experimental.
use serde::Serialize;
use std::time::Instant;

lazy_static! {
    static ref HALFLIFE_DECAY: f64 = -(2.0f64.ln()) / SCORE_HALFLIFE;
}

/// The default score for new peers.
pub(crate) const DEFAULT_SCORE: f64 = 0.0;
/// The minimum reputation before a peer is disconnected.
const MIN_SCORE_BEFORE_DISCONNECT: f64 = -20.0;
/// The minimum reputation before a peer is banned.
const MIN_SCORE_BEFORE_BAN: f64 = -50.0;
/// The maximum score a peer can obtain.
const MAX_SCORE: f64 = 100.0;
/// The minimum score a peer can obtain.
const MIN_SCORE: f64 = -100.0;
/// The halflife of a peer's score. I.e the number of seconds it takes for the score to decay to half its value.
const SCORE_HALFLIFE: f64 = 600.0;
/// The number of seconds we ban a peer for before their score begins to decay.
const BANNED_BEFORE_DECAY: u64 = 1800;

const GOSSIPSUB_NEGATIVE_SCORE_WEIGHT: f64 = 1.0;
const GOSSIPSUB_POSITIVE_SCORE_WEIGHT: f64 = 1.0;

/// A collection of actions a peer can perform which will adjust its score.
/// Each variant has an associated score change.
// To easily assess the behaviour of scores changes the number of variants should stay low, and
// somewhat generic.
#[derive(Debug, Clone, Copy)]
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
    /// NOTE: ~15 occurrences will get the peer banned
    HighToleranceError,
    /// Received an expected message.
    _ValidMessage,
}

impl std::fmt::Display for PeerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAction::Fatal => write!(f, "Fatal"),
            PeerAction::LowToleranceError => write!(f, "Low Tolerance Error"),
            PeerAction::MidToleranceError => write!(f, "Mid Tolerance Error"),
            PeerAction::HighToleranceError => write!(f, "High Tolerance Error"),
            PeerAction::_ValidMessage => write!(f, "Valid Message"),
        }
    }
}

/// The expected state of the peer given the peer's score.
#[derive(Debug, PartialEq)]
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
    /// The time the score was last updated to perform time-based adjustments such as score-decay.
    #[serde(skip)]
    last_updated: Instant,
}

impl Default for RealScore {
    fn default() -> Self {
        RealScore {
            lighthouse_score: DEFAULT_SCORE,
            gossipsub_score: DEFAULT_SCORE,
            last_updated: Instant::now(),
        }
    }
}

impl RealScore {
    /// Access to the underlying score.
    pub fn score(&self) -> f64 {
        self.lighthouse_score + self.gossipsub_score * if self.gossipsub_score > 0.0 {
            GOSSIPSUB_POSITIVE_SCORE_WEIGHT
        } else {
            GOSSIPSUB_NEGATIVE_SCORE_WEIGHT
        }
    }

    /// Modifies the score based on a peer's action.
    pub fn apply_peer_action(&mut self, peer_action: PeerAction) {
        match peer_action {
            PeerAction::Fatal => self.lighthouse_score = MIN_SCORE, // The worst possible score
            PeerAction::LowToleranceError => self.add(-10.0),
            PeerAction::MidToleranceError => self.add(-5.0),
            PeerAction::HighToleranceError => self.add(-1.0),
            PeerAction::_ValidMessage => self.add(0.1),
        }
    }

    /// Add an f64 to the score abiding by the limits.
    pub fn add(&mut self, score: f64) {
        let mut new_score = self.lighthouse_score + score;
        if new_score > MAX_SCORE {
            new_score = MAX_SCORE;
        }
        if new_score < MIN_SCORE {
            new_score = MIN_SCORE;
        }

        self.lighthouse_score = new_score;
    }

    /// Applies time-based logic such as decay rates to the score.
    /// This function should be called periodically.
    pub fn update(&mut self) {
        // Apply decay logic
        //
        // There is two distinct decay processes. One for banned peers and one for all others. If
        // the score is below the banning threshold and the duration since it was last update is
        // shorter than the banning threshold, we do nothing.
        let now = Instant::now();
        if self.lighthouse_score <= MIN_SCORE_BEFORE_BAN
            && now
                .checked_duration_since(self.last_updated)
                .map(|d| d.as_secs())
                <= Some(BANNED_BEFORE_DECAY)
        {
            // The peer is banned and still within the ban timeout. Do not update it's score.
            // Update last_updated so that the decay begins correctly when ready.
            self.last_updated = now;
            return;
        }

        // Decay the current score
        // Using exponential decay based on a constant half life.
        if let Some(secs_since_update) = now
            .checked_duration_since(self.last_updated)
            .map(|d| d.as_secs())
        {
            // e^(-ln(2)/HL*t)
            let decay_factor = (*HALFLIFE_DECAY * secs_since_update as f64).exp();
            self.lighthouse_score *= decay_factor;
            self.last_updated = now;
        }
    }

    pub fn update_gossipsub_score(&mut self, new_score: f64) {
        //TODO: only update gossipsub score if peer is not banned or after BANNED_BEFORE_DECAY
        self.gossipsub_score = new_score;
    }
}

#[derive(PartialEq, Clone, Debug, Serialize)]
pub enum Score {
    Max,
    Real(RealScore)
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
apply!(add, delta: f64);
apply!(update);
apply!(update_gossipsub_score, new_score: f64);

impl Score {
    pub fn score(&self) -> f64 {
        match self {
            Self::Max => f64::INFINITY,
            Self::Real(score) => score.score()
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
}

impl Eq for Score {}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Score) -> Option<std::cmp::Ordering> {
        self.score()
            .partial_cmp(&other.score())
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Score) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .unwrap_or_else(|| std::cmp::Ordering::Equal)
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
    fn test_reputation_change() {
        let mut score = Score::default();

        // 0 change does not change de reputation
        //
        let change = 0.0;
        score.add(change);
        assert_eq!(score.score(), DEFAULT_SCORE);

        // underflowing change is capped
        let mut score = Score::default();
        let change = MIN_SCORE - 50.0;
        score.add(change);
        assert_eq!(score.score(), MIN_SCORE);

        // overflowing change is capped
        let mut score = Score::default();
        let change = MAX_SCORE + 50.0;
        score.add(change);
        assert_eq!(score.score(), MAX_SCORE);

        // Score adjusts
        let mut score = Score::default();
        let change = 1.32;
        score.add(change);
        assert_eq!(score.score(), DEFAULT_SCORE + change);
    }
}
