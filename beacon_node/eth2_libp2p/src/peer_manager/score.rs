//! This contains the scoring logic for peers.
//!
//! A peer's score is a rational number in the range [-100, 100].
//!
//! As the logic develops this documentation will advance.
//!
//! The scoring algorithms are currently experimental.


/// The default score for new peers.
const DEFAULT_SCORE: f64 = 50;

/// The minimum reputation before a peer is banned.
const MIN_SCORE_BEFORE_BAN: f64 = -50;

/// The maximum score a peer can obtain.
const MAX_SCORE: f64 = 100;

/// The minimum score a peer can obtain.
const MIN_SCORE: f64 = -100;

/// A collection of actions a peer can perform which will adjust its score.
/// Each variant has an associated score change.
// To easily assess the behaviour of scores changes the number of variants should stay low, and
// somewhat generic.
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

impl PeerAction {
    fn score_change(&self) -> ScoreChange {
        match self {
        }
    }
}

/// A peer's score (perceived potential usefulness)
pub struct Score(f64);

impl Default for Score {
    fn default() -> Self {
        Self(DEFAULT_SCORE)
    }
}

impl From<f64> for Score {
    fn from(f: f64) -> Self {
        Score(f)
    }
}

impl Add for Score {
    type Output = Score;

    fn add(self, other: Score) -> Score {
        // apply the maximum cap
        let new_score = self.0 + other.0;
        if new_score > MAX_SCORE {
            Score(MAX_SCORE)
        } else {
            Score(new_score)
        }
    }
}

impl Sub for Score {
    type Output = Score;

    fn sub(self, other: Score) -> Score {
        let new_score = self.0 - other.0;
        if new_score < MIN_SCORE {
            Score(MIN_SCORE) 
        }
        else {
            Score(new_score)
        }
    }
}



impl Score {
    /// Modifies the score based on a peer's action.
    pub fn peer_action(&mut self, peer_action: PeerAction) {
        match peer_action {
            PeerAction::Fatal => *self = MIN_SCORE.into(), // The worst possible score
            PeerAction::LowToleranceError =>  *self = *self + Score(-20.0),
            PeerAction::MidToleranceError => RepChange::bad(25),
            PeerAction::HighToleranceError => RepChange::bad(15),
            PeerAction::_ValidMessage => RepChange::good(20),




    }


}


