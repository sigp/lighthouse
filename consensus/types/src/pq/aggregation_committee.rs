use milhouse::Vector;
use ssz_types::ProgressiveVariableList;

use crate::core::EthSpec;

/// The aggregators of a beacon committee (the spec's
/// `AggregationCommittee = ProgressiveList[ValidatorIndex]`).
pub type AggregationCommittee = ProgressiveVariableList<u64>;

/// The aggregation committee of each beacon committee of a slot, in committee order (the spec's
/// `AggregationCommittees = ProgressiveList[AggregationCommittee]`).
pub type AggregationCommittees = ProgressiveVariableList<AggregationCommittee>;

/// A rolling window of the aggregation committees of the previous, current, and lookahead
/// epochs (the spec's `AggregationCommitteeWindow`), of length
/// `(MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH`.
pub type AggregationCommitteeWindow<E> =
    Vector<AggregationCommittees, <E as EthSpec>::AggregationCommitteeWindowLength>;
