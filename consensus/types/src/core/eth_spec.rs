use std::{
    fmt::{self, Debug},
    str::FromStr,
};

use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use typenum::{U, Unsigned};

use crate::core::{ChainSpec, Epoch};

const MAINNET: &str = "mainnet";
const MINIMAL: &str = "minimal";
pub const GNOSIS: &str = "gnosis";

/// Used to identify one of the `EthSpec` instances defined here.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EthSpecId {
    Mainnet,
    Minimal,
    Gnosis,
}

impl FromStr for EthSpecId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            MAINNET => Ok(EthSpecId::Mainnet),
            MINIMAL => Ok(EthSpecId::Minimal),
            GNOSIS => Ok(EthSpecId::Gnosis),
            _ => Err(format!("Unknown eth spec: {}", s)),
        }
    }
}

impl fmt::Display for EthSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EthSpecId::Mainnet => MAINNET,
            EthSpecId::Minimal => MINIMAL,
            EthSpecId::Gnosis => GNOSIS,
        };
        write!(f, "{}", s)
    }
}

pub trait EthSpec: 'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq {
    /*
     * Constants
     */
    type GenesisEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type JustificationBitsLength: Unsigned + Clone + Sync + Send + Debug + PartialEq + Default;
    type SubnetBitfieldLength: Unsigned + Clone + Sync + Send + Debug + PartialEq + Default;
    /*
     * Misc
     */
    type MaxValidatorsPerCommittee: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type MaxValidatorsPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    type MaxCommitteesPerSlot: Unsigned + Clone + Sync + Send + Debug + PartialEq + Eq;
    /*
     * Time parameters
     */
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerEth1VotingPeriod: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * State list lengths
     */
    type EpochsPerHistoricalVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerSlashingsVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type HistoricalRootsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * Max operations per block
     */
    type MaxProposerSlashings: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttesterSlashings: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDeposits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxVoluntaryExits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Altair
     */
    type SyncCommitteeSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /// The number of `sync_committee` subnets.
    type SyncCommitteeSubnetCount: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Bellatrix
     */
    type MaxBytesPerTransaction: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxTransactionsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type BytesPerLogsBloom: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type GasLimitDenominator: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxExtraDataBytes: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Capella
     */
    type MaxBlsToExecutionChanges: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Deneb
     */
    type MaxBlobCommitmentsPerBlock: Unsigned + Clone + Sync + Send + Debug + PartialEq + Unpin;
    type FieldElementsPerBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type BytesPerFieldElement: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type KzgCommitmentInclusionProofDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Fulu
     */
    type FieldElementsPerCell: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type FieldElementsPerExtBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type KzgCommitmentsInclusionProofDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type CellsPerExtBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type NumberOfColumns: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ProposerLookaheadSlots: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * Derived values (set these CAREFULLY)
     */
    /// The length of the `{previous,current}_epoch_attestations` lists.
    ///
    /// Must be set to `MaxAttestations * SlotsPerEpoch`
    // NOTE: we could safely instantiate these by using type-level arithmetic, but doing
    // so adds ~25s to the time required to type-check this crate
    type MaxPendingAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /// The length of `eth1_data_votes`.
    ///
    /// Must be set to `EpochsPerEth1VotingPeriod * SlotsPerEpoch`
    type SlotsPerEth1VotingPeriod: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /// The size of `sync_subcommittees`.
    ///
    /// Must be set to `SyncCommitteeSize / SyncCommitteeSubnetCount`.
    type SyncSubcommitteeSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /// The total length of a blob in bytes.
    ///
    /// Must be set to `BytesPerFieldElement * FieldElementsPerBlob`.
    type BytesPerBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /// The total length of a data column in bytes.
    ///
    /// Must be set to `BytesPerFieldElement * FieldElementsPerCell`.
    type BytesPerCell: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /// The maximum number of cell commitments per block
    ///
    /// FieldElementsPerExtBlob * MaxBlobCommitmentsPerBlock
    type MaxCellsPerBlock: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /*
     * New in Electra
     */
    type PendingDepositsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingConsolidationsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxConsolidationRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDepositRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttesterSlashingsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttestationsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxPendingDepositsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /*
     * New in Gloas
     */
    type PTCSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PtcWindowLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxPayloadAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type BuilderPendingPaymentsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxBuildersPerWithdrawalsSweep: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxBuilderDepositRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxBuilderExitRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /*
     * New in Heze
     */
    type InclusionListCommitteeSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn default_spec() -> ChainSpec;

    fn spec_name() -> EthSpecId;

    fn genesis_epoch() -> Epoch {
        Epoch::new(Self::GenesisEpoch::to_u64())
    }

    /// Return the number of committees per slot.
    ///
    /// Note: the number of committees per slot is constant in each epoch, and depends only on
    /// the `active_validator_count` during the slot's epoch.
    ///
    /// Spec v0.12.1
    fn get_committee_count_per_slot(
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> Result<usize, ArithError> {
        Self::get_committee_count_per_slot_with(
            active_validator_count,
            spec.max_committees_per_slot,
            spec.target_committee_size,
        )
    }

    fn get_committee_count_per_slot_with(
        active_validator_count: usize,
        max_committees_per_slot: usize,
        target_committee_size: usize,
    ) -> Result<usize, ArithError> {
        let slots_per_epoch = Self::SlotsPerEpoch::to_usize();

        Ok(std::cmp::max(
            1,
            std::cmp::min(
                max_committees_per_slot,
                active_validator_count
                    .safe_div(slots_per_epoch)?
                    .safe_div(target_committee_size)?,
            ),
        ))
    }

    /// Returns the minimum number of validators required for this spec.
    ///
    /// This is the _absolute_ minimum, the number required to make the chain operate in the most
    /// basic sense. This count is not required to provide any security guarantees regarding
    /// decentralization, entropy, etc.
    fn minimum_validator_count() -> usize {
        Self::SlotsPerEpoch::to_usize()
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }

    /// Returns the `SLOTS_PER_HISTORICAL_ROOT` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_historical_root() -> usize {
        Self::SlotsPerHistoricalRoot::to_usize()
    }

    /// Returns the `EPOCHS_PER_HISTORICAL_VECTOR` constant for this specification.
    ///
    /// Spec v0.12.1
    fn epochs_per_historical_vector() -> usize {
        Self::EpochsPerHistoricalVector::to_usize()
    }

    /// Returns the `SLOTS_PER_ETH1_VOTING_PERIOD` constant for this specification.
    ///
    /// Spec v0.12.1
    fn slots_per_eth1_voting_period() -> usize {
        Self::SlotsPerEth1VotingPeriod::to_usize()
    }

    /// Returns the `SYNC_COMMITTEE_SIZE` constant for this specification.
    fn sync_committee_size() -> usize {
        Self::SyncCommitteeSize::to_usize()
    }

    /// Returns the `SYNC_COMMITTEE_SIZE / SyncCommitteeSubnetCount`.
    fn sync_subcommittee_size() -> usize {
        Self::SyncSubcommitteeSize::to_usize()
    }

    /// Returns the `MAX_BYTES_PER_TRANSACTION` constant for this specification.
    fn max_bytes_per_transaction() -> usize {
        Self::MaxBytesPerTransaction::to_usize()
    }

    /// Returns the `MAX_TRANSACTIONS_PER_PAYLOAD` constant for this specification.
    fn max_transactions_per_payload() -> usize {
        Self::MaxTransactionsPerPayload::to_usize()
    }

    /// Returns the `MAX_EXTRA_DATA_BYTES` constant for this specification.
    fn max_extra_data_bytes() -> usize {
        Self::MaxExtraDataBytes::to_usize()
    }

    /// Returns the `BYTES_PER_LOGS_BLOOM` constant for this specification.
    fn bytes_per_logs_bloom() -> usize {
        Self::BytesPerLogsBloom::to_usize()
    }

    /// Returns the `MAX_BLS_TO_EXECUTION_CHANGES` constant for this specification.
    fn max_bls_to_execution_changes() -> usize {
        Self::MaxBlsToExecutionChanges::to_usize()
    }

    /// Returns the `MAX_WITHDRAWALS_PER_PAYLOAD` constant for this specification.
    fn max_withdrawals_per_payload() -> usize {
        Self::MaxWithdrawalsPerPayload::to_usize()
    }

    /// Returns the `MAX_BLOB_COMMITMENTS_PER_BLOCK` constant for this specification.
    fn max_blob_commitments_per_block() -> usize {
        Self::MaxBlobCommitmentsPerBlock::to_usize()
    }

    /// Returns the `FIELD_ELEMENTS_PER_BLOB` constant for this specification.
    fn field_elements_per_blob() -> usize {
        Self::FieldElementsPerBlob::to_usize()
    }

    /// Returns the `FIELD_ELEMENTS_PER_EXT_BLOB` constant for this specification.
    fn field_elements_per_ext_blob() -> usize {
        Self::FieldElementsPerExtBlob::to_usize()
    }

    /// Returns the `FIELD_ELEMENTS_PER_CELL` constant for this specification.
    fn field_elements_per_cell() -> usize {
        Self::FieldElementsPerCell::to_usize()
    }

    /// Returns the `BYTES_PER_BLOB` constant for this specification.
    fn bytes_per_blob() -> usize {
        Self::BytesPerBlob::to_usize()
    }

    /// Returns the `BYTES_PER_CELL` constant for this specification.
    fn bytes_per_cell() -> usize {
        Self::BytesPerCell::to_usize()
    }

    /// Returns the `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` preset for this specification.
    fn kzg_proof_inclusion_proof_depth() -> usize {
        Self::KzgCommitmentInclusionProofDepth::to_usize()
    }

    fn kzg_commitments_tree_depth() -> usize {
        // Depth of the subtree rooted at `blob_kzg_commitments` in the `BeaconBlockBody`
        // is equal to depth of the ssz List max size + 1 for the length mixin
        Self::max_blob_commitments_per_block()
            .next_power_of_two()
            .ilog2()
            .safe_add(1)
            .expect("The log of max_blob_commitments_per_block can not overflow") as usize
    }

    fn block_body_tree_depth() -> usize {
        Self::kzg_proof_inclusion_proof_depth()
            .safe_sub(Self::kzg_commitments_tree_depth())
            .expect("Preset values are not configurable and never result in non-positive block body depth")
    }

    /// Returns the `PENDING_DEPOSITS_LIMIT` constant for this specification.
    fn pending_deposits_limit() -> usize {
        Self::PendingDepositsLimit::to_usize()
    }

    /// Returns the `PENDING_PARTIAL_WITHDRAWALS_LIMIT` constant for this specification.
    fn pending_partial_withdrawals_limit() -> usize {
        Self::PendingPartialWithdrawalsLimit::to_usize()
    }

    /// Returns the `PENDING_CONSOLIDATIONS_LIMIT` constant for this specification.
    fn pending_consolidations_limit() -> usize {
        Self::PendingConsolidationsLimit::to_usize()
    }

    /// Returns the `BUILDER_PENDING_PAYMENTS_LIMIT` constant for this specification.
    fn builder_pending_payments_limit() -> usize {
        Self::BuilderPendingPaymentsLimit::to_usize()
    }

    /// Returns the `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` constant for this specification.
    fn max_consolidation_requests_per_payload() -> usize {
        Self::MaxConsolidationRequestsPerPayload::to_usize()
    }

    /// Returns the `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD` constant for this specification.
    fn max_deposit_requests_per_payload() -> usize {
        Self::MaxDepositRequestsPerPayload::to_usize()
    }

    /// Returns the `MAX_ATTESTER_SLASHINGS_ELECTRA` constant for this specification.
    fn max_attester_slashings_electra() -> usize {
        Self::MaxAttesterSlashingsElectra::to_usize()
    }

    /// Returns the `MAX_ATTESTATIONS_ELECTRA` constant for this specification.
    fn max_attestations_electra() -> usize {
        Self::MaxAttestationsElectra::to_usize()
    }

    /// Returns the `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD` constant for this specification.
    fn max_withdrawal_requests_per_payload() -> usize {
        Self::MaxWithdrawalRequestsPerPayload::to_usize()
    }

    /// Returns the `MAX_PENDING_DEPOSITS_PER_EPOCH` constant for this specification.
    fn max_pending_deposits_per_epoch() -> usize {
        Self::MaxPendingDepositsPerEpoch::to_usize()
    }

    fn kzg_commitments_inclusion_proof_depth() -> usize {
        Self::KzgCommitmentsInclusionProofDepth::to_usize()
    }

    fn cells_per_ext_blob() -> usize {
        Self::CellsPerExtBlob::to_usize()
    }

    fn number_of_columns() -> usize {
        Self::NumberOfColumns::to_usize()
    }

    fn proposer_lookahead_slots() -> usize {
        Self::ProposerLookaheadSlots::to_usize()
    }

    /// Returns the `PTCSize` constant for this specification.
    fn ptc_size() -> usize {
        Self::PTCSize::to_usize()
    }

    /// Returns the `PtcWindowLength` constant for this specification.
    fn ptc_window_length() -> usize {
        Self::PtcWindowLength::to_usize()
    }

    /// Returns the `MaxPayloadAttestations` constant for this specification.
    fn max_payload_attestations() -> usize {
        Self::MaxPayloadAttestations::to_usize()
    }

    /// Returns the `MaxBuildersPerWithdrawalsSweep` constant for this specification.
    fn max_builders_per_withdrawals_sweep() -> usize {
        Self::MaxBuildersPerWithdrawalsSweep::to_usize()
    }

    /// Returns the `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD` constant for this specification.
    fn max_builder_deposit_requests_per_payload() -> usize {
        Self::MaxBuilderDepositRequestsPerPayload::to_usize()
    }

    /// Returns the `MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD` constant for this specification.
    fn max_builder_exit_requests_per_payload() -> usize {
        Self::MaxBuilderExitRequestsPerPayload::to_usize()
    }

    /// Returns the `MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE` constant for this specification.
    fn max_signed_aggregate_and_proof_size() -> usize;

    /// Returns the `MAX_ATTESTER_SLASHING_SIZE` constant for this specification.
    fn max_attester_slashing_size() -> usize;

    /// Returns the `MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE` constant for this specification.
    fn max_signed_execution_payload_bid_size() -> usize;

    /// Returns the `MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE` constant for this specification.
    fn max_signed_execution_payload_bid_size_heze() -> usize;

    /// Returns the `MAX_SIGNED_INCLUSION_LIST_SIZE` constant for this specification.
    fn max_signed_inclusion_list_size() -> usize;

    /// Returns the `PAYLOAD_TIMELY_THRESHOLD` constant (PTC_SIZE / 2).
    fn payload_timely_threshold() -> usize {
        Self::PTCSize::to_usize() / 2
    }

    /// Returns the `DATA_AVAILABILITY_TIMELY_THRESHOLD` constant (PTC_SIZE / 2).
    fn data_availability_timely_threshold() -> usize {
        Self::PTCSize::to_usize() / 2
    }

    /// Returns the `INCLUSION_LIST_COMMITTEE_SIZE` constant for this specification.
    fn inclusion_list_committee_size() -> usize {
        Self::InclusionListCommitteeSize::to_usize()
    }
}

/// Sets each typenum type from its preset const (the values are in `spec.rs`).
macro_rules! preset_types {
    ($spec:ident) => {
        type GenesisEpoch = U<{ $spec::GENESIS_EPOCH }>;
        type JustificationBitsLength = U<{ $spec::JUSTIFICATION_BITS_LENGTH }>;
        type SubnetBitfieldLength = U<{ $spec::SUBNET_BITFIELD_LENGTH }>;
        type MaxValidatorsPerCommittee = U<{ $spec::MAX_VALIDATORS_PER_COMMITTEE }>;
        type MaxCommitteesPerSlot = U<{ $spec::MAX_COMMITTEES_PER_SLOT }>;
        type MaxValidatorsPerSlot = U<{ $spec::MAX_VALIDATORS_PER_SLOT }>;
        type SlotsPerEpoch = U<{ $spec::SLOTS_PER_EPOCH }>;
        type EpochsPerEth1VotingPeriod = U<{ $spec::EPOCHS_PER_ETH1_VOTING_PERIOD }>;
        type SlotsPerHistoricalRoot = U<{ $spec::SLOTS_PER_HISTORICAL_ROOT }>;
        type EpochsPerHistoricalVector = U<{ $spec::EPOCHS_PER_HISTORICAL_VECTOR }>;
        type EpochsPerSlashingsVector = U<{ $spec::EPOCHS_PER_SLASHINGS_VECTOR }>;
        type HistoricalRootsLimit = U<{ $spec::HISTORICAL_ROOTS_LIMIT }>;
        type ValidatorRegistryLimit = U<{ $spec::VALIDATOR_REGISTRY_LIMIT }>;
        type BuilderPendingPaymentsLimit = U<{ $spec::BUILDER_PENDING_PAYMENTS_LIMIT }>;
        type MaxProposerSlashings = U<{ $spec::MAX_PROPOSER_SLASHINGS }>;
        type MaxAttesterSlashings = U<{ $spec::MAX_ATTESTER_SLASHINGS }>;
        type MaxAttestations = U<{ $spec::MAX_ATTESTATIONS }>;
        type MaxDeposits = U<{ $spec::MAX_DEPOSITS }>;
        type MaxVoluntaryExits = U<{ $spec::MAX_VOLUNTARY_EXITS }>;
        type SyncCommitteeSize = U<{ $spec::SYNC_COMMITTEE_SIZE }>;
        type SyncCommitteeSubnetCount = U<{ $spec::SYNC_COMMITTEE_SUBNET_COUNT }>;
        type MaxBytesPerTransaction = U<{ $spec::MAX_BYTES_PER_TRANSACTION }>;
        type MaxTransactionsPerPayload = U<{ $spec::MAX_TRANSACTIONS_PER_PAYLOAD }>;
        type BytesPerLogsBloom = U<{ $spec::BYTES_PER_LOGS_BLOOM }>;
        type GasLimitDenominator = U<{ $spec::GAS_LIMIT_DENOMINATOR }>;
        type MaxExtraDataBytes = U<{ $spec::MAX_EXTRA_DATA_BYTES }>;
        type MaxBlsToExecutionChanges = U<{ $spec::MAX_BLS_TO_EXECUTION_CHANGES }>;
        type MaxWithdrawalsPerPayload = U<{ $spec::MAX_WITHDRAWALS_PER_PAYLOAD }>;
        type MaxBlobCommitmentsPerBlock = U<{ $spec::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;
        type BytesPerFieldElement = U<{ $spec::BYTES_PER_FIELD_ELEMENT }>;
        type FieldElementsPerBlob = U<{ $spec::FIELD_ELEMENTS_PER_BLOB }>;
        type FieldElementsPerCell = U<{ $spec::FIELD_ELEMENTS_PER_CELL }>;
        type FieldElementsPerExtBlob = U<{ $spec::FIELD_ELEMENTS_PER_EXT_BLOB }>;
        type BytesPerBlob = U<{ $spec::BYTES_PER_BLOB }>;
        type BytesPerCell = U<{ $spec::BYTES_PER_CELL }>;
        type MaxCellsPerBlock = U<{ $spec::MAX_CELLS_PER_BLOCK }>;
        type KzgCommitmentInclusionProofDepth = U<{ $spec::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH }>;
        type KzgCommitmentsInclusionProofDepth =
            U<{ $spec::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH }>;
        type CellsPerExtBlob = U<{ $spec::CELLS_PER_EXT_BLOB }>;
        type NumberOfColumns = U<{ $spec::NUMBER_OF_COLUMNS }>;
        type ProposerLookaheadSlots = U<{ $spec::PROPOSER_LOOKAHEAD_SLOTS }>;
        type SyncSubcommitteeSize = U<{ $spec::SYNC_SUBCOMMITTEE_SIZE }>;
        type MaxPendingAttestations = U<{ $spec::MAX_PENDING_ATTESTATIONS }>;
        type SlotsPerEth1VotingPeriod = U<{ $spec::SLOTS_PER_ETH1_VOTING_PERIOD }>;
        type PendingDepositsLimit = U<{ $spec::PENDING_DEPOSITS_LIMIT }>;
        type PendingPartialWithdrawalsLimit = U<{ $spec::PENDING_PARTIAL_WITHDRAWALS_LIMIT }>;
        type PendingConsolidationsLimit = U<{ $spec::PENDING_CONSOLIDATIONS_LIMIT }>;
        type MaxConsolidationRequestsPerPayload =
            U<{ $spec::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD }>;
        type MaxDepositRequestsPerPayload = U<{ $spec::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD }>;
        type MaxAttesterSlashingsElectra = U<{ $spec::MAX_ATTESTER_SLASHINGS_ELECTRA }>;
        type MaxAttestationsElectra = U<{ $spec::MAX_ATTESTATIONS_ELECTRA }>;
        type MaxWithdrawalRequestsPerPayload = U<{ $spec::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD }>;
        type MaxPendingDepositsPerEpoch = U<{ $spec::MAX_PENDING_DEPOSITS_PER_EPOCH }>;
        type PTCSize = U<{ $spec::PTC_SIZE }>;
        type PtcWindowLength = U<{ $spec::PTC_WINDOW_LENGTH }>;
        type MaxPayloadAttestations = U<{ $spec::MAX_PAYLOAD_ATTESTATIONS }>;
        type MaxBuildersPerWithdrawalsSweep = U<{ $spec::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP }>;
        type MaxBuilderDepositRequestsPerPayload =
            U<{ $spec::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD }>;
        type MaxBuilderExitRequestsPerPayload = U<{ $spec::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD }>;
        type InclusionListCommitteeSize = U<{ $spec::INCLUSION_LIST_COMMITTEE_SIZE }>;
    };
}

/// Ethereum Foundation specifications.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MainnetEthSpec;

impl EthSpec for MainnetEthSpec {
    preset_types!(MainnetEthSpec);

    fn default_spec() -> ChainSpec {
        ChainSpec::mainnet()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Mainnet
    }

    fn max_signed_aggregate_and_proof_size() -> usize {
        16829
    }

    fn max_attester_slashing_size() -> usize {
        2097616
    }

    fn max_signed_execution_payload_bid_size() -> usize {
        196932
    }

    fn max_signed_execution_payload_bid_size_heze() -> usize {
        196934
    }

    fn max_signed_inclusion_list_size() -> usize {
        41112
    }
}

/// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    preset_types!(MinimalEthSpec);

    fn default_spec() -> ChainSpec {
        ChainSpec::minimal()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Minimal
    }

    fn max_signed_aggregate_and_proof_size() -> usize {
        1462
    }

    fn max_attester_slashing_size() -> usize {
        131536
    }

    fn max_signed_execution_payload_bid_size() -> usize {
        196932
    }

    fn max_signed_execution_payload_bid_size_heze() -> usize {
        196934
    }

    fn max_signed_inclusion_list_size() -> usize {
        41112
    }
}

/// Gnosis Beacon Chain specifications.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct GnosisEthSpec;

impl EthSpec for GnosisEthSpec {
    preset_types!(GnosisEthSpec);

    fn default_spec() -> ChainSpec {
        ChainSpec::gnosis()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Gnosis
    }

    fn max_signed_aggregate_and_proof_size() -> usize {
        16829
    }

    fn max_attester_slashing_size() -> usize {
        2097616
    }

    fn max_signed_execution_payload_bid_size() -> usize {
        196932
    }

    fn max_signed_execution_payload_bid_size_heze() -> usize {
        196934
    }

    fn max_signed_inclusion_list_size() -> usize {
        41112
    }
}

#[cfg(test)]
mod test {
    use crate::{EthSpec, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec, Spec};
    use typenum::Unsigned;

    fn assert_valid_spec<E: EthSpec>() {
        let spec = E::default_spec();
        E::kzg_commitments_tree_depth();
        E::block_body_tree_depth();
        assert!(E::MaxValidatorsPerSlot::to_i32() >= E::MaxValidatorsPerCommittee::to_i32());
        assert_eq!(
            E::proposer_lookahead_slots(),
            (spec.min_seed_lookahead.as_usize() + 1) * E::slots_per_epoch() as usize
        );
        assert_eq!(
            E::ptc_window_length(),
            (spec.min_seed_lookahead.as_usize() + 2) * E::slots_per_epoch() as usize,
            "PtcWindowLength must equal (2 + MIN_SEED_LOOKAHEAD) * SLOTS_PER_EPOCH"
        );
    }

    #[test]
    fn mainnet_spec() {
        assert_valid_spec::<MainnetEthSpec>();
    }
    #[test]
    fn minimal_spec() {
        assert_valid_spec::<MinimalEthSpec>();
    }
    #[test]
    fn gnosis_spec() {
        assert_valid_spec::<GnosisEthSpec>();
    }

    /// Whichever preset was compiled in must be a valid one.
    #[test]
    fn compiled_spec() {
        assert_valid_spec::<Spec>();
    }
}
