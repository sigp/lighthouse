use crate::*;

use safe_arith::SafeArith;
use serde::{Deserialize, Serialize};
use ssz_types::typenum::{
    bit::B0, UInt, U0, U1, U1024, U1048576, U1073741824, U1099511627776, U128, U131072, U134217728,
    U16, U16777216, U2, U2048, U256, U262144, U32, U4, U4096, U512, U6, U625, U64, U65536, U8,
    U8192,
};
use ssz_types::typenum::{U17, U9};
use std::fmt::{self, Debug};
use std::str::FromStr;

pub type U5000 = UInt<UInt<UInt<U625, B0>, B0>, B0>; // 625 * 8 = 5000

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

pub trait EthSpec:
    'static + Default + Sync + Send + Clone + Debug + PartialEq + Eq + for<'a> arbitrary::Arbitrary<'a>
{
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
    type MinGasLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxExtraDataBytes: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Capella
     */
    type MaxBlsToExecutionChanges: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in Deneb
     */
    type MaxBlobsPerBlock: Unsigned + Clone + Sync + Send + Debug + PartialEq + Unpin;
    type MaxBlobCommitmentsPerBlock: Unsigned + Clone + Sync + Send + Debug + PartialEq + Unpin;
    type FieldElementsPerBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type BytesPerFieldElement: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type KzgCommitmentInclusionProofDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * New in PeerDAS
     */
    type FieldElementsPerCell: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type FieldElementsPerExtBlob: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type KzgCommitmentsInclusionProofDepth: Unsigned + Clone + Sync + Send + Debug + PartialEq;
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

    /*
     * New in Electra
     */
    type PendingBalanceDepositsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingPartialWithdrawalsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type PendingConsolidationsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxConsolidationRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDepositRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttesterSlashingsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttestationsElectra: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxWithdrawalRequestsPerPayload: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /*
     * New in EIP-7736
     */
    type PTCSize: Unsigned + Clone + Sync + Send + Debug + PartialEq;

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
    ) -> Result<usize, Error> {
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
    ) -> Result<usize, Error> {
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

    /// Returns the `MAX_BLOBS_PER_BLOCK` constant for this specification.
    fn max_blobs_per_block() -> usize {
        Self::MaxBlobsPerBlock::to_usize()
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

    /// Returns the `PENDING_BALANCE_DEPOSITS_LIMIT` constant for this specification.
    fn pending_balance_deposits_limit() -> usize {
        Self::PendingBalanceDepositsLimit::to_usize()
    }

    /// Returns the `PENDING_PARTIAL_WITHDRAWALS_LIMIT` constant for this specification.
    fn pending_partial_withdrawals_limit() -> usize {
        Self::PendingPartialWithdrawalsLimit::to_usize()
    }

    /// Returns the `PENDING_CONSOLIDATIONS_LIMIT` constant for this specification.
    fn pending_consolidations_limit() -> usize {
        Self::PendingConsolidationsLimit::to_usize()
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

    fn kzg_commitments_inclusion_proof_depth() -> usize {
        Self::KzgCommitmentsInclusionProofDepth::to_usize()
    }
}

/// Macro to inherit some type values from another EthSpec.
#[macro_export]
macro_rules! params_from_eth_spec {
    ($spec_ty:ty { $($ty_name:ident),+ }) => {
        $(type $ty_name = <$spec_ty as EthSpec>::$ty_name;)+
    }
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MainnetEthSpec;

impl EthSpec for MainnetEthSpec {
    type JustificationBitsLength = U4;
    type SubnetBitfieldLength = U64;
    type MaxValidatorsPerCommittee = U2048;
    type MaxCommitteesPerSlot = U64;
    type MaxValidatorsPerSlot = U131072;
    type GenesisEpoch = U0;
    type SlotsPerEpoch = U32;
    type EpochsPerEth1VotingPeriod = U64;
    type SlotsPerHistoricalRoot = U8192;
    type EpochsPerHistoricalVector = U65536;
    type EpochsPerSlashingsVector = U8192;
    type HistoricalRootsLimit = U16777216;
    type ValidatorRegistryLimit = U1099511627776;
    type MaxProposerSlashings = U16;
    type MaxAttesterSlashings = U2;
    type MaxAttestations = U128;
    type MaxDeposits = U16;
    type MaxVoluntaryExits = U16;
    type SyncCommitteeSize = U512;
    type SyncCommitteeSubnetCount = U4;
    type MaxBytesPerTransaction = U1073741824; // 1,073,741,824
    type MaxTransactionsPerPayload = U1048576; // 1,048,576
    type BytesPerLogsBloom = U256;
    type GasLimitDenominator = U1024;
    type MinGasLimit = U5000;
    type MaxExtraDataBytes = U32;
    type MaxBlobsPerBlock = U6;
    type MaxBlobCommitmentsPerBlock = U4096;
    type BytesPerFieldElement = U32;
    type FieldElementsPerBlob = U4096;
    type FieldElementsPerCell = U64;
    type FieldElementsPerExtBlob = U8192;
    type BytesPerBlob = U131072;
    type BytesPerCell = U2048;
    type KzgCommitmentInclusionProofDepth = U17;
    type KzgCommitmentsInclusionProofDepth = U4; // inclusion of the whole list of commitments
    type SyncSubcommitteeSize = U128; // 512 committee size / 4 sync committee subnet count
    type MaxPendingAttestations = U4096; // 128 max attestations * 32 slots per epoch
    type SlotsPerEth1VotingPeriod = U2048; // 64 epochs * 32 slots per epoch
    type MaxBlsToExecutionChanges = U16;
    type MaxWithdrawalsPerPayload = U16;
    type PendingBalanceDepositsLimit = U134217728;
    type PendingPartialWithdrawalsLimit = U134217728;
    type PendingConsolidationsLimit = U262144;
    type MaxConsolidationRequestsPerPayload = U1;
    type MaxDepositRequestsPerPayload = U8192;
    type MaxAttesterSlashingsElectra = U1;
    type MaxAttestationsElectra = U8;
    type MaxWithdrawalRequestsPerPayload = U16;
    type PTCSize = U512;

    fn default_spec() -> ChainSpec {
        ChainSpec::mainnet()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Mainnet
    }
}

/// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    type MaxCommitteesPerSlot = U4;
    type MaxValidatorsPerSlot = U8192;
    type SlotsPerEpoch = U8;
    type EpochsPerEth1VotingPeriod = U4;
    type SlotsPerHistoricalRoot = U64;
    type EpochsPerHistoricalVector = U64;
    type EpochsPerSlashingsVector = U64;
    type SyncCommitteeSize = U32;
    type SyncSubcommitteeSize = U8; // 32 committee size / 4 sync committee subnet count
    type MaxPendingAttestations = U1024; // 128 max attestations * 8 slots per epoch
    type SlotsPerEth1VotingPeriod = U32; // 4 epochs * 8 slots per epoch
    type MaxWithdrawalsPerPayload = U4;
    type FieldElementsPerBlob = U4096;
    type BytesPerBlob = U131072;
    type MaxBlobCommitmentsPerBlock = U16;
    type KzgCommitmentInclusionProofDepth = U9;
    type PendingPartialWithdrawalsLimit = U64;
    type PendingConsolidationsLimit = U64;
    type MaxDepositRequestsPerPayload = U4;
    type MaxWithdrawalRequestsPerPayload = U2;
    type FieldElementsPerCell = U64;
    type FieldElementsPerExtBlob = U8192;
    type BytesPerCell = U2048;
    type KzgCommitmentsInclusionProofDepth = U4;

    params_from_eth_spec!(MainnetEthSpec {
        JustificationBitsLength,
        SubnetBitfieldLength,
        SyncCommitteeSubnetCount,
        MaxValidatorsPerCommittee,
        GenesisEpoch,
        HistoricalRootsLimit,
        ValidatorRegistryLimit,
        MaxProposerSlashings,
        MaxAttesterSlashings,
        MaxAttestations,
        MaxDeposits,
        MaxVoluntaryExits,
        MaxBytesPerTransaction,
        MaxTransactionsPerPayload,
        BytesPerLogsBloom,
        GasLimitDenominator,
        MinGasLimit,
        MaxExtraDataBytes,
        MaxBlsToExecutionChanges,
        MaxBlobsPerBlock,
        BytesPerFieldElement,
        PendingBalanceDepositsLimit,
        MaxConsolidationRequestsPerPayload,
        MaxAttesterSlashingsElectra,
        MaxAttestationsElectra,
        PTCSize
    });

    fn default_spec() -> ChainSpec {
        ChainSpec::minimal()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Minimal
    }
}

/// Gnosis Beacon Chain specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct GnosisEthSpec;

impl EthSpec for GnosisEthSpec {
    type JustificationBitsLength = U4;
    type SubnetBitfieldLength = U64;
    type MaxValidatorsPerCommittee = U2048;
    type MaxCommitteesPerSlot = U64;
    type MaxValidatorsPerSlot = U131072;
    type GenesisEpoch = U0;
    type SlotsPerEpoch = U16;
    type EpochsPerEth1VotingPeriod = U64;
    type SlotsPerHistoricalRoot = U8192;
    type EpochsPerHistoricalVector = U65536;
    type EpochsPerSlashingsVector = U8192;
    type HistoricalRootsLimit = U16777216;
    type ValidatorRegistryLimit = U1099511627776;
    type MaxProposerSlashings = U16;
    type MaxAttesterSlashings = U2;
    type MaxAttestations = U128;
    type MaxDeposits = U16;
    type MaxVoluntaryExits = U16;
    type SyncCommitteeSize = U512;
    type SyncCommitteeSubnetCount = U4;
    type MaxBytesPerTransaction = U1073741824; // 1,073,741,824
    type MaxTransactionsPerPayload = U1048576; // 1,048,576
    type BytesPerLogsBloom = U256;
    type GasLimitDenominator = U1024;
    type MinGasLimit = U5000;
    type MaxExtraDataBytes = U32;
    type SyncSubcommitteeSize = U128; // 512 committee size / 4 sync committee subnet count
    type MaxPendingAttestations = U2048; // 128 max attestations * 16 slots per epoch
    type SlotsPerEth1VotingPeriod = U1024; // 64 epochs * 16 slots per epoch
    type MaxBlsToExecutionChanges = U16;
    type MaxWithdrawalsPerPayload = U8;
    type MaxBlobsPerBlock = U6;
    type MaxBlobCommitmentsPerBlock = U4096;
    type FieldElementsPerBlob = U4096;
    type BytesPerFieldElement = U32;
    type BytesPerBlob = U131072;
    type KzgCommitmentInclusionProofDepth = U17;
    type PendingBalanceDepositsLimit = U134217728;
    type PendingPartialWithdrawalsLimit = U134217728;
    type PendingConsolidationsLimit = U262144;
    type MaxConsolidationRequestsPerPayload = U1;
    type MaxDepositRequestsPerPayload = U8192;
    type MaxAttesterSlashingsElectra = U1;
    type MaxAttestationsElectra = U8;
    type MaxWithdrawalRequestsPerPayload = U16;
    type FieldElementsPerCell = U64;
    type FieldElementsPerExtBlob = U8192;
    type BytesPerCell = U2048;
    type KzgCommitmentsInclusionProofDepth = U4;
    type PTCSize = U512;

    fn default_spec() -> ChainSpec {
        ChainSpec::gnosis()
    }

    fn spec_name() -> EthSpecId {
        EthSpecId::Gnosis
    }
}

#[cfg(test)]
mod test {
    use crate::{EthSpec, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};
    use ssz_types::typenum::Unsigned;

    fn assert_valid_spec<E: EthSpec>() {
        E::kzg_commitments_tree_depth();
        E::block_body_tree_depth();
        assert!(E::MaxValidatorsPerSlot::to_i32() >= E::MaxValidatorsPerCommittee::to_i32());
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
}
