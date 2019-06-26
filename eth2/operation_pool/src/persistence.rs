use crate::attestation_id::AttestationId;
use crate::OperationPool;
use parking_lot::RwLock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::*;

/// SSZ-serializable version of `OperationPool`.
///
/// Operations are stored in arbitrary order, so it's not a good idea to compare instances
/// of this type (or its encoded form) for equality. Convert back to an `OperationPool` first.
#[derive(Encode, Decode)]
pub struct PersistedOperationPool {
    /// Mapping from attestation ID to attestation mappings.
    // We could save space by not storing the attestation ID, but it might
    // be difficult to make that roundtrip due to eager aggregation.
    attestations: Vec<SszPair<AttestationId, Vec<Attestation>>>,
    deposits: Vec<Deposit>,
    /// Attester slashings.
    attester_slashings: Vec<AttesterSlashing>,
    /// Proposer slashings.
    proposer_slashings: Vec<ProposerSlashing>,
    /// Voluntary exits.
    voluntary_exits: Vec<VoluntaryExit>,
    /// Transfers.
    transfers: Vec<Transfer>,
}

impl PersistedOperationPool {
    /// Convert an `OperationPool` into serializable form.
    pub fn from_operation_pool<T: EthSpec>(operation_pool: &OperationPool<T>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|(att_id, att)| SszPair::new(att_id.clone(), att.clone()))
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
            .map(|(_, slashing)| slashing.clone())
            .collect();

        let proposer_slashings = operation_pool
            .proposer_slashings
            .read()
            .iter()
            .map(|(_, slashing)| slashing.clone())
            .collect();

        let voluntary_exits = operation_pool
            .voluntary_exits
            .read()
            .iter()
            .map(|(_, exit)| exit.clone())
            .collect();

        let transfers = operation_pool.transfers.read().iter().cloned().collect();

        Self {
            attestations,
            deposits,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            transfers,
        }
    }

    /// Reconstruct an `OperationPool`.
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
        let proposer_slashings = RwLock::new(
            self.proposer_slashings
                .into_iter()
                .map(|slashing| (slashing.proposer_index, slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits
                .into_iter()
                .map(|exit| (exit.validator_index, exit))
                .collect(),
        );
        let transfers = RwLock::new(self.transfers.into_iter().collect());

        OperationPool {
            attestations,
            deposits,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            transfers,
            _phantom: Default::default(),
        }
    }
}

/// Tuples for SSZ.
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
