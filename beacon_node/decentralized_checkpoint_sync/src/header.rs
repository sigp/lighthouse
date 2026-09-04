use crate::{LightClientStoreSchema, LightClientSyncError};
use merkle_proof::verify_merkle_proof;
use tree_hash::TreeHash;
use types::{
    BeaconBlockHeader, ChainSpec, EthSpec, ExecutionPayloadHeaderCapella, ForkName, Hash256,
    LightClientHeader,
    light_client::consts::{EXECUTION_PAYLOAD_INDEX, EXECUTION_PAYLOAD_PROOF_LEN},
};

/// Return the beacon block header contained in a light-client header.
pub fn beacon_header<E: EthSpec>(header: &LightClientHeader<E>) -> &BeaconBlockHeader {
    match header {
        LightClientHeader::Altair(inner) => &inner.beacon,
        LightClientHeader::Capella(inner) => &inner.beacon,
        LightClientHeader::Deneb(inner) => &inner.beacon,
        LightClientHeader::Electra(inner) => &inner.beacon,
        LightClientHeader::Fulu(inner) => &inner.beacon,
    }
}

/// Verify that `header` is valid for its wire-data fork and beacon slot.
///
/// `data_fork` is the fork used to decode the enclosing light-client object. It can be newer than
/// the fork at `header.beacon.slot` because stores upgrade older headers to their current schema.
/// It cannot be older, because an older schema cannot represent all fields from a newer block.
pub fn validate_light_client_header<E: EthSpec>(
    header: &LightClientHeader<E>,
    data_fork: ForkName,
    spec: &ChainSpec,
) -> Result<(), LightClientSyncError> {
    LightClientStoreSchema::try_from(data_fork)?;
    ensure_header_variant(header, data_fork)?;

    let beacon_header_fork = spec.fork_name_at_slot::<E>(beacon_header(header).slot);
    LightClientStoreSchema::try_from(beacon_header_fork)?;

    if data_fork < beacon_header_fork {
        return Err(LightClientSyncError::DataForkBeforeBeaconHeaderFork {
            data_fork,
            beacon_header_fork,
        });
    }

    if !beacon_header_fork.capella_enabled() {
        return validate_pre_capella_header(header);
    }

    if !beacon_header_fork.deneb_enabled() && has_non_zero_blob_gas_fields(header) {
        return Err(LightClientSyncError::NonZeroBlobGasFields);
    }

    let execution_root = execution_root(header, beacon_header_fork)?;
    let execution_branch = execution_branch(header)?;
    if verify_merkle_proof(
        execution_root,
        execution_branch,
        EXECUTION_PAYLOAD_PROOF_LEN,
        EXECUTION_PAYLOAD_INDEX,
        beacon_header(header).body_root,
    ) {
        Ok(())
    } else {
        Err(LightClientSyncError::InvalidExecutionPayloadProof)
    }
}

fn ensure_header_variant<E: EthSpec>(
    header: &LightClientHeader<E>,
    data_fork: ForkName,
) -> Result<(), LightClientSyncError> {
    let matches = matches!(
        (header, data_fork),
        (
            LightClientHeader::Altair(_),
            ForkName::Altair | ForkName::Bellatrix
        ) | (LightClientHeader::Capella(_), ForkName::Capella)
            | (LightClientHeader::Deneb(_), ForkName::Deneb)
            | (LightClientHeader::Electra(_), ForkName::Electra)
            | (LightClientHeader::Fulu(_), ForkName::Fulu)
    );

    if matches {
        Ok(())
    } else {
        Err(LightClientSyncError::HeaderVariantMismatch {
            expected: data_fork,
            actual: header_variant(header),
        })
    }
}

fn header_variant<E: EthSpec>(header: &LightClientHeader<E>) -> ForkName {
    match header {
        LightClientHeader::Altair(_) => ForkName::Altair,
        LightClientHeader::Capella(_) => ForkName::Capella,
        LightClientHeader::Deneb(_) => ForkName::Deneb,
        LightClientHeader::Electra(_) => ForkName::Electra,
        LightClientHeader::Fulu(_) => ForkName::Fulu,
    }
}

fn validate_pre_capella_header<E: EthSpec>(
    header: &LightClientHeader<E>,
) -> Result<(), LightClientSyncError> {
    if !execution_payload_is_default(header) {
        return Err(LightClientSyncError::NonDefaultExecutionPayload);
    }
    if !execution_branch_is_default(header) {
        return Err(LightClientSyncError::NonDefaultExecutionBranch);
    }
    Ok(())
}

fn execution_payload_is_default<E: EthSpec>(header: &LightClientHeader<E>) -> bool {
    match header {
        LightClientHeader::Altair(_) => true,
        LightClientHeader::Capella(inner) => inner.execution == Default::default(),
        LightClientHeader::Deneb(inner) => inner.execution == Default::default(),
        LightClientHeader::Electra(inner) => inner.execution == Default::default(),
        LightClientHeader::Fulu(inner) => inner.execution == Default::default(),
    }
}

fn execution_branch_is_default<E: EthSpec>(header: &LightClientHeader<E>) -> bool {
    match header {
        LightClientHeader::Altair(_) => true,
        LightClientHeader::Capella(inner) => inner
            .execution_branch
            .iter()
            .all(|root| *root == Hash256::default()),
        LightClientHeader::Deneb(inner) => inner
            .execution_branch
            .iter()
            .all(|root| *root == Hash256::default()),
        LightClientHeader::Electra(inner) => inner
            .execution_branch
            .iter()
            .all(|root| *root == Hash256::default()),
        LightClientHeader::Fulu(inner) => inner
            .execution_branch
            .iter()
            .all(|root| *root == Hash256::default()),
    }
}

fn has_non_zero_blob_gas_fields<E: EthSpec>(header: &LightClientHeader<E>) -> bool {
    match header {
        LightClientHeader::Altair(_) | LightClientHeader::Capella(_) => false,
        LightClientHeader::Deneb(inner) => {
            inner.execution.blob_gas_used != 0 || inner.execution.excess_blob_gas != 0
        }
        LightClientHeader::Electra(inner) => {
            inner.execution.blob_gas_used != 0 || inner.execution.excess_blob_gas != 0
        }
        LightClientHeader::Fulu(inner) => {
            inner.execution.blob_gas_used != 0 || inner.execution.excess_blob_gas != 0
        }
    }
}

fn execution_branch<E: EthSpec>(
    header: &LightClientHeader<E>,
) -> Result<&[Hash256], LightClientSyncError> {
    match header {
        LightClientHeader::Altair(_) => Err(LightClientSyncError::HeaderVariantMismatch {
            expected: ForkName::Capella,
            actual: ForkName::Altair,
        }),
        LightClientHeader::Capella(inner) => Ok(inner.execution_branch.as_ref()),
        LightClientHeader::Deneb(inner) => Ok(inner.execution_branch.as_ref()),
        LightClientHeader::Electra(inner) => Ok(inner.execution_branch.as_ref()),
        LightClientHeader::Fulu(inner) => Ok(inner.execution_branch.as_ref()),
    }
}

fn execution_root<E: EthSpec>(
    header: &LightClientHeader<E>,
    beacon_header_fork: ForkName,
) -> Result<Hash256, LightClientSyncError> {
    match header {
        LightClientHeader::Altair(_) => Err(LightClientSyncError::HeaderVariantMismatch {
            expected: beacon_header_fork,
            actual: ForkName::Altair,
        }),
        LightClientHeader::Capella(inner) => Ok(inner.execution.tree_hash_root()),
        LightClientHeader::Deneb(inner) => {
            execution_root_for_post_capella_header(&inner.execution, beacon_header_fork)
        }
        LightClientHeader::Electra(inner) => {
            execution_root_for_post_capella_header(&inner.execution, beacon_header_fork)
        }
        LightClientHeader::Fulu(inner) => {
            execution_root_for_post_capella_header(&inner.execution, beacon_header_fork)
        }
    }
}

fn execution_root_for_post_capella_header<E: EthSpec, H: PostCapellaExecutionHeader<E>>(
    execution: &H,
    beacon_header_fork: ForkName,
) -> Result<Hash256, LightClientSyncError> {
    if beacon_header_fork.deneb_enabled() {
        Ok(execution.tree_hash_root())
    } else {
        Ok(execution.as_capella().tree_hash_root())
    }
}

trait PostCapellaExecutionHeader<E: EthSpec>: TreeHash {
    fn as_capella(&self) -> ExecutionPayloadHeaderCapella<E>;
}

macro_rules! impl_post_capella_execution_header {
    ($type:ident) => {
        impl<E: EthSpec> PostCapellaExecutionHeader<E> for types::$type<E> {
            fn as_capella(&self) -> ExecutionPayloadHeaderCapella<E> {
                ExecutionPayloadHeaderCapella {
                    parent_hash: self.parent_hash,
                    fee_recipient: self.fee_recipient,
                    state_root: self.state_root,
                    receipts_root: self.receipts_root,
                    logs_bloom: self.logs_bloom.clone(),
                    prev_randao: self.prev_randao,
                    block_number: self.block_number,
                    gas_limit: self.gas_limit,
                    gas_used: self.gas_used,
                    timestamp: self.timestamp,
                    extra_data: self.extra_data.clone(),
                    base_fee_per_gas: self.base_fee_per_gas,
                    block_hash: self.block_hash,
                    transactions_root: self.transactions_root,
                    withdrawals_root: self.withdrawals_root,
                }
            }
        }
    };
}

impl_post_capella_execution_header!(ExecutionPayloadHeaderDeneb);
impl_post_capella_execution_header!(ExecutionPayloadHeaderElectra);
impl_post_capella_execution_header!(ExecutionPayloadHeaderFulu);

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_proof::merkle_root_from_branch;
    use types::{
        EthSpec, LightClientHeaderAltair, LightClientHeaderCapella, LightClientHeaderDeneb,
        LightClientHeaderElectra, LightClientHeaderFulu, MinimalEthSpec,
    };

    type E = MinimalEthSpec;

    #[test]
    fn validates_headers_for_each_supported_fork() {
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ] {
            let spec = fork.make_genesis_spec(E::default_spec());
            let header = valid_header(fork);
            assert_eq!(validate_light_client_header(&header, fork, &spec), Ok(()));
        }
    }

    #[test]
    fn rejects_header_variant_mismatch() {
        let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
        let header = valid_header(ForkName::Deneb);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::HeaderVariantMismatch {
                expected: ForkName::Capella,
                actual: ForkName::Deneb,
            })
        );
    }

    #[test]
    fn rejects_execution_payload_not_committed_by_body_root() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let mut header = valid_header(ForkName::Capella);
        if let LightClientHeader::Capella(inner) = &mut header {
            inner.execution.block_number = 1;
        }
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::InvalidExecutionPayloadProof)
        );
    }

    #[test]
    fn rejects_corrupt_execution_branch() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let mut header = valid_header(ForkName::Capella);
        if let LightClientHeader::Capella(inner) = &mut header
            && let Some(first) = inner.execution_branch.get_mut(0)
        {
            *first = Hash256::repeat_byte(0x42);
        }
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::InvalidExecutionPayloadProof)
        );
    }

    #[test]
    fn validates_default_upgraded_pre_capella_header() {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let header = LightClientHeader::Capella(LightClientHeaderCapella::<E>::default());
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Ok(())
        );
    }

    #[test]
    fn rejects_non_default_pre_capella_execution_payload() {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let mut inner = LightClientHeaderCapella::<E>::default();
        inner.execution.block_number = 1;
        let header = LightClientHeader::Capella(inner);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::NonDefaultExecutionPayload)
        );
    }

    #[test]
    fn rejects_non_default_pre_capella_execution_branch() {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let mut inner = LightClientHeaderCapella::<E>::default();
        if let Some(first) = inner.execution_branch.get_mut(0) {
            *first = Hash256::repeat_byte(0x42);
        }
        let header = LightClientHeader::Capella(inner);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::NonDefaultExecutionBranch)
        );
    }

    #[test]
    fn validates_deneb_schema_header_from_capella() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let mut inner = LightClientHeaderDeneb::<E>::default();
        set_valid_execution_root(
            &mut inner.beacon,
            &inner.execution.as_capella(),
            &inner.execution_branch,
        );
        let header = LightClientHeader::Deneb(inner);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Deneb, &spec),
            Ok(())
        );
    }

    #[test]
    fn rejects_non_zero_blob_gas_fields_before_deneb() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let mut inner = LightClientHeaderDeneb::<E>::default();
        inner.execution.blob_gas_used = 1;
        let header = LightClientHeader::Deneb(inner);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Deneb, &spec),
            Err(LightClientSyncError::NonZeroBlobGasFields)
        );
    }

    #[test]
    fn rejects_data_fork_older_than_beacon_header_fork() {
        let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
        let header = valid_header(ForkName::Capella);
        assert_eq!(
            validate_light_client_header(&header, ForkName::Capella, &spec),
            Err(LightClientSyncError::DataForkBeforeBeaconHeaderFork {
                data_fork: ForkName::Capella,
                beacon_header_fork: ForkName::Deneb,
            })
        );
    }

    #[test]
    fn rejects_unsupported_forks() {
        let header = valid_header(ForkName::Fulu);
        for fork in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
            let spec = fork.make_genesis_spec(E::default_spec());
            assert_eq!(
                validate_light_client_header(&header, fork, &spec),
                Err(LightClientSyncError::UnsupportedFork(fork))
            );
        }

        let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
        assert_eq!(
            validate_light_client_header(&header, ForkName::Fulu, &spec),
            Err(LightClientSyncError::UnsupportedFork(ForkName::Gloas))
        );
    }

    fn valid_header(fork: ForkName) -> LightClientHeader<E> {
        match fork {
            ForkName::Altair | ForkName::Bellatrix => {
                LightClientHeader::Altair(LightClientHeaderAltair::default())
            }
            ForkName::Capella => {
                let mut inner = LightClientHeaderCapella::<E>::default();
                set_valid_execution_root(
                    &mut inner.beacon,
                    &inner.execution,
                    &inner.execution_branch,
                );
                LightClientHeader::Capella(inner)
            }
            ForkName::Deneb => {
                let mut inner = LightClientHeaderDeneb::<E>::default();
                set_valid_execution_root(
                    &mut inner.beacon,
                    &inner.execution,
                    &inner.execution_branch,
                );
                LightClientHeader::Deneb(inner)
            }
            ForkName::Electra => {
                let mut inner = LightClientHeaderElectra::<E>::default();
                set_valid_execution_root(
                    &mut inner.beacon,
                    &inner.execution,
                    &inner.execution_branch,
                );
                LightClientHeader::Electra(inner)
            }
            ForkName::Fulu => {
                let mut inner = LightClientHeaderFulu::<E>::default();
                set_valid_execution_root(
                    &mut inner.beacon,
                    &inner.execution,
                    &inner.execution_branch,
                );
                LightClientHeader::Fulu(inner)
            }
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                LightClientHeader::Altair(LightClientHeaderAltair::default())
            }
        }
    }

    fn set_valid_execution_root<H: TreeHash>(
        beacon: &mut BeaconBlockHeader,
        execution: &H,
        branch: &[Hash256],
    ) {
        beacon.body_root = merkle_root_from_branch(
            execution.tree_hash_root(),
            branch,
            EXECUTION_PAYLOAD_PROOF_LEN,
            EXECUTION_PAYLOAD_INDEX,
        );
    }
}
