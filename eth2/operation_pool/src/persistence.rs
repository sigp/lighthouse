use crate::attestation_id::AttestationId;
use crate::OperationPool;
use itertools::Itertools;
use parking_lot::RwLock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::*;

/// Tuples for SSZ
#[derive(Encode, Decode)]
struct SszPair<X: Encode + Decode, Y: Encode + Decode> {
    x: X,
    y: Y,
}

impl<X: Encode + Decode, Y: Encode + Decode> SszPair<X, Y> {
    fn new(x: X, y: Y) -> Self {
        Self { x, y }
    }
}

impl<X, Y> From<(X, Y)> for SszPair<X, Y>
where
    X: Encode + Decode,
    Y: Encode + Decode,
{
    fn from((x, y): (X, Y)) -> Self {
        Self { x, y }
    }
}

impl<X, Y> Into<(X, Y)> for SszPair<X, Y>
where
    X: Encode + Decode,
    Y: Encode + Decode,
{
    fn into(self) -> (X, Y) {
        (self.x, self.y)
    }
}

#[derive(Encode, Decode)]
pub struct PersistedOperationPool {
    /// Mapping from attestation ID to attestation mappings, sorted by ID.
    // TODO: we could save space by not storing the attestation ID, but it might
    // be difficult to make that roundtrip due to eager aggregation.
    attestations: Vec<SszPair<AttestationId, Vec<Attestation>>>,
    deposits: Vec<Deposit>,
    /// Attester slashings sorted by their pair of attestation IDs (not stored).
    attester_slashings: Vec<AttesterSlashing>,
}

impl PersistedOperationPool {
    pub fn from_operation_pool<T: EthSpec>(operation_pool: &OperationPool<T>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|(att_id, att)| SszPair::new(att_id.clone(), att.clone()))
            .sorted_by(|att1, att2| Ord::cmp(&att1.x, &att2.x))
            .collect();

        let deposits = operation_pool
            .deposits
            .read()
            .iter()
            .map(|(_, d)| d.clone())
            .collect();

        let attester_slashings = operation_pool
            .attester_slashings
            .read()
            .iter()
            .sorted_by(|(id1, _), (id2, _)| Ord::cmp(&id1, &id2))
            .map(|(_, slashing)| slashing.clone())
            .collect();

        Self {
            attestations,
            deposits,
            attester_slashings,
        }
    }

    pub fn into_operation_pool<T: EthSpec>(
        self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> OperationPool<T> {
        let attestations = RwLock::new(self.attestations.into_iter().map(SszPair::into).collect());
        let deposits = RwLock::new(self.deposits.into_iter().map(|d| (d.index, d)).collect());
        let attester_slashings = RwLock::new(
            self.attester_slashings
                .into_iter()
                .map(|slashing| {
                    (
                        OperationPool::attester_slashing_id(&slashing, state, spec),
                        slashing,
                    )
                })
                .collect(),
        );

        OperationPool {
            attestations,
            deposits,
            attester_slashings,
            // TODO
            ..OperationPool::new()
        }
    }
}
