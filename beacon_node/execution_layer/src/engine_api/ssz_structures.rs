use crate::json_structures::{BlobAndProofV2, BlobAndProofV3};

use super::json_structures::RequestsError;
use super::*;
use serde::Deserialize;
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitVector, VariableList};
use std::collections::HashSet;
use superstruct::superstruct;
use typenum::{U1, U32};
use types::execution::{
    BuilderDepositRequests, BuilderExitRequests, ConsolidationRequests, DepositRequests,
    ExecutionRequestsElectra, ExecutionRequestsGloas, RequestType, WithdrawalRequests,
};
use types::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas, ExecutionRequests,
    ForkName,
};
use types::{EthSpec, Transactions};

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszExecutionPayloadBody<E: EthSpec> {
    pub transactions: Transactions<E>,
    #[superstruct(only(V2, V3))]
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(V3))]
    pub block_access_list: VariableList<u8, E::MaxBytesPerTransaction>,
}

impl<E: EthSpec> From<SszExecutionPayloadBodyV1<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: SszExecutionPayloadBodyV1<E>) -> Self {
        Self {
            transactions: value.transactions,
            withdrawals: None,
        }
    }
}

impl<E: EthSpec> From<ExecutionPayloadBodyV1<E>> for SszExecutionPayloadBodyV1<E> {
    fn from(value: ExecutionPayloadBodyV1<E>) -> Self {
        Self {
            transactions: value.transactions,
        }
    }
}

impl<E: EthSpec> From<SszExecutionPayloadBodyV2<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: SszExecutionPayloadBodyV2<E>) -> Self {
        Self {
            transactions: value.transactions,
            withdrawals: Some(value.withdrawals),
        }
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV1<E>> for SszExecutionPayloadBodyV2<E> {
    type Error = String;

    fn try_from(value: ExecutionPayloadBodyV1<E>) -> Result<Self, String> {
        let withdrawals = value.withdrawals.ok_or_else(|| {
            "execution payload body is missing withdrawals; \
             a body without withdrawals cannot be a Shanghai (or later) body"
                .to_string()
        })?;
        Ok(Self {
            transactions: value.transactions,
            withdrawals,
        })
    }
}

impl<E: EthSpec> From<SszExecutionPayloadBodyV3<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: SszExecutionPayloadBodyV3<E>) -> Self {
        // FIXME(rest-ssz): needs `ExecutionPayloadBodyV1 += block_access_list: Option<..>`
        // impl once block_access_list is added to ExecutionPayloadBodyV1
        Self {
            transactions: value.transactions,
            withdrawals: Some(value.withdrawals),
        }
    }
}

//ExecutionPayloadBodyV1 <-> SszExecutionPayloadBodyV3 conversion support to be impl once block_access_list is added to ExecutionPayloadBodyV1

type SszExecutionRequests<E> = VariableList<
    VariableList<u8, <E as EthSpec>::MaxBytesPerTransaction>,
    <E as EthSpec>::MaxExecutionRequestsPerPayload,
>;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    map_into(ExecutionPayload),
    cast_error(
        ty = "Error",
        expr = "Error::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "Error",
        expr = "Error::IncorrectStateVariant"
    )
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszExecutionPayloadEnvelope<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    pub execution_payload: ExecutionPayloadFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_payload_gloas"))]
    pub execution_payload: ExecutionPayloadGloas<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas))]
    pub parent_beacon_block_root: Hash256,
    #[superstruct(only(Electra, Fulu, Gloas))]
    pub execution_requests: SszExecutionRequests<E>,
}

impl<'block, E: EthSpec> From<NewPayloadRequestBellatrix<'block, E>>
    for SszExecutionPayloadEnvelopeBellatrix<E>
{
    fn from(value: NewPayloadRequestBellatrix<E>) -> Self {
        Self {
            execution_payload: value.execution_payload.clone(),
        }
    }
}

impl<'block, E: EthSpec> From<NewPayloadRequestCapella<'block, E>>
    for SszExecutionPayloadEnvelopeCapella<E>
{
    fn from(value: NewPayloadRequestCapella<E>) -> Self {
        Self {
            execution_payload: value.execution_payload.clone(),
        }
    }
}

impl<'block, E: EthSpec> From<NewPayloadRequestDeneb<'block, E>>
    for SszExecutionPayloadEnvelopeDeneb<E>
{
    fn from(value: NewPayloadRequestDeneb<'block, E>) -> Self {
        Self {
            execution_payload: value.execution_payload.clone(),
            parent_beacon_block_root: value.parent_beacon_block_root,
        }
    }
}

impl<'block, E: EthSpec> TryFrom<NewPayloadRequestElectra<'block, E>>
    for SszExecutionPayloadEnvelopeElectra<E>
{
    type Error = ssz_types::Error;
    fn try_from(value: NewPayloadRequestElectra<'block, E>) -> Result<Self, Self::Error> {
        Ok(Self {
            execution_payload: value.execution_payload.clone(),
            parent_beacon_block_root: value.parent_beacon_block_root,
            execution_requests: execution_requests_to_ssz(ExecutionRequests::Electra(
                value.execution_requests.clone(),
            ))?,
        })
    }
}

impl<'block, E: EthSpec> TryFrom<NewPayloadRequestFulu<'block, E>>
    for SszExecutionPayloadEnvelopeFulu<E>
{
    type Error = ssz_types::Error;
    fn try_from(value: NewPayloadRequestFulu<'block, E>) -> Result<Self, Self::Error> {
        Ok(Self {
            execution_payload: value.execution_payload.clone(),
            parent_beacon_block_root: value.parent_beacon_block_root,
            execution_requests: execution_requests_to_ssz(ExecutionRequests::Electra(
                value.execution_requests.clone(),
            ))?,
        })
    }
}

impl<'block, E: EthSpec> TryFrom<NewPayloadRequestGloas<'block, E>>
    for SszExecutionPayloadEnvelopeGloas<E>
{
    type Error = ssz_types::Error;
    fn try_from(value: NewPayloadRequestGloas<'block, E>) -> Result<Self, Self::Error> {
        Ok(Self {
            execution_payload: value.execution_payload.clone(),
            parent_beacon_block_root: value.parent_beacon_block_root,
            execution_requests: execution_requests_to_ssz(ExecutionRequests::Gloas(
                value.execution_requests.clone(),
            ))?,
        })
    }
}

pub fn execution_requests_to_ssz<E>(
    req: ExecutionRequests<E>,
) -> Result<SszExecutionRequests<E>, ssz_types::Error>
where
    E: EthSpec,
{
    let requests = req
        .get_execution_requests_list()
        .into_iter()
        .map(|bytes| VariableList::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;

    VariableList::new(requests)
}

/// Parse an EIP-7685 SSZ requests list into its component request lists.
///
/// Returns the deposit, withdrawal, consolidation, builder deposit and builder exit lists.
/// Builder lists are empty pre-gloas or post-gloas when no builder requests are present.
#[allow(clippy::type_complexity)]
fn parse_execution_requests_ssz<E>(
    ssz_requests: SszExecutionRequests<E>,
) -> Result<
    (
        DepositRequests<E>,
        WithdrawalRequests<E>,
        ConsolidationRequests<E>,
        BuilderDepositRequests<E>,
        BuilderExitRequests<E>,
    ),
    RequestsError,
>
where
    E: EthSpec,
{
    let mut deposits = DepositRequests::<E>::default();
    let mut withdrawals = WithdrawalRequests::<E>::default();
    let mut consolidations = ConsolidationRequests::<E>::default();
    let mut builder_deposits = BuilderDepositRequests::<E>::default();
    let mut builder_exits = BuilderExitRequests::<E>::default();
    let mut prev_prefix: Option<RequestType> = None;

    for (i, request) in ssz_requests.iter().enumerate() {
        let request_bytes: &[u8] = request;

        // The first byte is the `request_type`; the remaining bytes are the `request_data`.
        // Elements with empty `request_data` **MUST** be excluded from the list.
        let Some((prefix_byte, request_data)) = request_bytes.split_first() else {
            return Err(RequestsError::EmptyRequest(i));
        };
        if request_data.is_empty() {
            return Err(RequestsError::EmptyRequest(i));
        }

        // Elements of the list **MUST** be ordered by `request_type` in ascending order.
        let current_prefix =
            RequestType::from_u8(*prefix_byte).ok_or(RequestsError::InvalidPrefix(*prefix_byte))?;
        if let Some(prev) = prev_prefix
            && prev.to_u8() >= current_prefix.to_u8()
        {
            return Err(RequestsError::InvalidOrdering);
        }
        prev_prefix = Some(current_prefix);

        match current_prefix {
            RequestType::Deposit => {
                deposits = DepositRequests::<E>::from_ssz_bytes(request_data).map_err(|e| {
                    RequestsError::DecodeError(format!(
                        "Failed to decode DepositRequest from EL: {:?}",
                        e
                    ))
                })?;
            }
            RequestType::Withdrawal => {
                withdrawals =
                    WithdrawalRequests::<E>::from_ssz_bytes(request_data).map_err(|e| {
                        RequestsError::DecodeError(format!(
                            "Failed to decode WithdrawalRequest from EL: {:?}",
                            e
                        ))
                    })?;
            }
            RequestType::Consolidation => {
                consolidations =
                    ConsolidationRequests::<E>::from_ssz_bytes(request_data).map_err(|e| {
                        RequestsError::DecodeError(format!(
                            "Failed to decode ConsolidationRequest from EL: {:?}",
                            e
                        ))
                    })?;
            }
            RequestType::BuilderDeposit => {
                builder_deposits = BuilderDepositRequests::<E>::from_ssz_bytes(request_data)
                    .map_err(|e| {
                        RequestsError::DecodeError(format!(
                            "Failed to decode BuilderDepositRequest from EL: {:?}",
                            e
                        ))
                    })?;
            }
            RequestType::BuilderExit => {
                builder_exits =
                    BuilderExitRequests::<E>::from_ssz_bytes(request_data).map_err(|e| {
                        RequestsError::DecodeError(format!(
                            "Failed to decode BuilderExitRequest from EL: {:?}",
                            e
                        ))
                    })?;
            }
        }
    }

    Ok((
        deposits,
        withdrawals,
        consolidations,
        builder_deposits,
        builder_exits,
    ))
}

fn execution_requests_electra_from_ssz<E>(
    ssz_requests: SszExecutionRequests<E>,
) -> Result<ExecutionRequestsElectra<E>, RequestsError>
where
    E: EthSpec,
{
    let (deposits, withdrawals, consolidations, builder_deposits, builder_exits) =
        parse_execution_requests_ssz::<E>(ssz_requests)?;
    // Builder requests are not valid pre-Gloas.
    if !builder_deposits.is_empty() || !builder_exits.is_empty() {
        return Err(RequestsError::VariantMismatch);
    }
    Ok(ExecutionRequestsElectra {
        deposits,
        withdrawals,
        consolidations,
    })
}

fn execution_requests_gloas_from_ssz<E>(
    ssz_requests: SszExecutionRequests<E>,
) -> Result<ExecutionRequestsGloas<E>, RequestsError>
where
    E: EthSpec,
{
    let (deposits, withdrawals, consolidations, builder_deposits, builder_exits) =
        parse_execution_requests_ssz::<E>(ssz_requests)?;
    Ok(ExecutionRequestsGloas {
        deposits,
        withdrawals,
        consolidations,
        builder_deposits,
        builder_exits,
    })
}

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct SszPayloadStatusV1<E: EthSpec> {
    pub payload_status: u8,
    pub latest_valid_hash: VariableList<Hash256, U1>,
    pub validation_error: VariableList<VariableList<u8, E::MaxErrorBytes>, U1>,
}

impl<E: EthSpec> TryFrom<SszPayloadStatusV1<E>> for PayloadStatusV1 {
    type Error = String;

    fn try_from(value: SszPayloadStatusV1<E>) -> Result<Self, Self::Error> {
        let status = match value.payload_status {
            0 => PayloadStatusV1Status::Valid,
            1 => PayloadStatusV1Status::Invalid,
            2 => PayloadStatusV1Status::Syncing,
            3 => PayloadStatusV1Status::Accepted,
            other => return Err(format!("invalid payload status {other} from EL")),
        };

        Ok(Self {
            status,
            latest_valid_hash: value
                .latest_valid_hash
                .first()
                .copied()
                .map(ExecutionBlockHash::from_root),
            validation_error: value
                .validation_error
                .first()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
        })
    }
}

impl<E: EthSpec> TryFrom<PayloadStatusV1> for SszPayloadStatusV1<E> {
    type Error = ssz_types::Error;

    fn try_from(value: PayloadStatusV1) -> Result<Self, Self::Error> {
        let status = match value.status {
            PayloadStatusV1Status::Valid => 0,
            PayloadStatusV1Status::Invalid => 1,
            PayloadStatusV1Status::Syncing => 2,
            PayloadStatusV1Status::Accepted => 3,
            // INVALID_BLOCK_HASH is folded into INVALID on the wire
            PayloadStatusV1Status::InvalidBlockHash => 1,
        };
        let latest_valid_hash = VariableList::new(
            value
                .latest_valid_hash
                .map(|h| h.into_root())
                .into_iter()
                .collect(),
        )?;

        let validation_error = VariableList::new(
            value
                .validation_error
                .map(|s| VariableList::new(s.into_bytes()))
                .transpose()?
                .into_iter()
                .collect(),
        )?;

        Ok(Self {
            payload_status: status,
            latest_valid_hash,
            validation_error,
        })
    }
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(derive(Debug, PartialEq, Encode, Decode),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Encode, Decode)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszGetPayloadResponse<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    pub execution_payload: ExecutionPayloadFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_payload_gloas"))]
    pub execution_payload: ExecutionPayloadGloas<E>,
    pub block_value: Uint256,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas))]
    pub blobs_bundle: BlobsBundle<E>,
    #[superstruct(only(Electra, Fulu, Gloas))]
    pub requests: SszExecutionRequests<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas), partial_getter(copy))]
    pub should_override_builder: bool,
}

impl<E: EthSpec> SszGetPayloadResponse<E> {
    pub fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        match fork {
            ForkName::Bellatrix => {
                SszGetPayloadResponseBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                SszGetPayloadResponseCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Deneb => SszGetPayloadResponseDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => {
                SszGetPayloadResponseElectra::from_ssz_bytes(bytes).map(Self::Electra)
            }
            ForkName::Fulu => SszGetPayloadResponseFulu::from_ssz_bytes(bytes).map(Self::Fulu),
            ForkName::Gloas => SszGetPayloadResponseGloas::from_ssz_bytes(bytes).map(Self::Gloas),
            ForkName::Base | ForkName::Altair => Err(DecodeError::BytesInvalid(format!(
                "unsupported fork for get_payload response: {fork}"
            ))),
        }
    }
}

impl<E: EthSpec> TryFrom<SszGetPayloadResponse<E>> for GetPayloadResponse<E> {
    type Error = RequestsError;

    fn try_from(value: SszGetPayloadResponse<E>) -> Result<Self, Self::Error> {
        match value {
            SszGetPayloadResponse::Bellatrix(response) => {
                Ok(GetPayloadResponse::Bellatrix(GetPayloadResponseBellatrix {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                }))
            }
            SszGetPayloadResponse::Capella(response) => {
                Ok(GetPayloadResponse::Capella(GetPayloadResponseCapella {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                }))
            }
            SszGetPayloadResponse::Deneb(response) => {
                Ok(GetPayloadResponse::Deneb(GetPayloadResponseDeneb {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    should_override_builder: response.should_override_builder,
                }))
            }
            SszGetPayloadResponse::Electra(response) => {
                Ok(GetPayloadResponse::Electra(GetPayloadResponseElectra {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    should_override_builder: response.should_override_builder,
                    requests: execution_requests_electra_from_ssz(response.requests)?,
                }))
            }
            SszGetPayloadResponse::Fulu(response) => {
                Ok(GetPayloadResponse::Fulu(GetPayloadResponseFulu {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    should_override_builder: response.should_override_builder,
                    requests: execution_requests_electra_from_ssz(response.requests)?,
                }))
            }
            SszGetPayloadResponse::Gloas(response) => {
                Ok(GetPayloadResponse::Gloas(GetPayloadResponseGloas {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    should_override_builder: response.should_override_builder,
                    requests: execution_requests_gloas_from_ssz(response.requests)?,
                }))
            }
        }
    }
}

/// Pre-Amsterdam SSZ `engine_forkchoiceUpdated` request body. Per-fork so the SSZ list element is
/// the concrete `PayloadAttributesV{N}` rather than the mixed-size transparent `PayloadAttributes`.
#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszForkchoiceUpdate {
    pub forkchoice_state: ForkchoiceState,
    #[superstruct(only(Bellatrix), partial_getter(rename = "payload_attributes_bellatrix"))]
    pub payload_attributes: VariableList<PayloadAttributesV1, U1>,
    #[superstruct(only(Capella), partial_getter(rename = "payload_attributes_capella"))]
    pub payload_attributes: VariableList<PayloadAttributesV2, U1>,
    #[superstruct(only(Deneb), partial_getter(rename = "payload_attributes_deneb"))]
    pub payload_attributes: VariableList<PayloadAttributesV3, U1>,
    #[superstruct(only(Electra), partial_getter(rename = "payload_attributes_electra"))]
    pub payload_attributes: VariableList<PayloadAttributesV3, U1>,
    #[superstruct(only(Fulu), partial_getter(rename = "payload_attributes_fulu"))]
    pub payload_attributes: VariableList<PayloadAttributesV3, U1>,
}

/// Amsterdam SSZ `engine_forkchoiceUpdated` request body (adds `custody_columns`).
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszForkchoiceUpdateAmsterdam<E: EthSpec> {
    pub forkchoice_state: ForkchoiceState,
    pub payload_attributes: VariableList<PayloadAttributesV4, U1>,
    pub custody_columns: VariableList<BitVector<E::CellsPerExtBlob>, U1>,
}

impl SszForkchoiceUpdate {
    pub fn new(
        fork: ForkName,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<Self, Error> {
        let update = match fork {
            ForkName::Bellatrix => Self::Bellatrix(SszForkchoiceUpdateBellatrix {
                forkchoice_state,
                payload_attributes: VariableList::new(
                    payload_attributes
                        .map(|attributes| attributes.as_v1().cloned())
                        .transpose()?
                        .into_iter()
                        .collect(),
                )?,
            }),
            ForkName::Capella => Self::Capella(SszForkchoiceUpdateCapella {
                forkchoice_state,
                payload_attributes: VariableList::new(
                    payload_attributes
                        .map(|attributes| attributes.as_v2().cloned())
                        .transpose()?
                        .into_iter()
                        .collect(),
                )?,
            }),
            ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
                let payload_attributes = VariableList::new(
                    payload_attributes
                        .map(|attributes| attributes.as_v3().cloned())
                        .transpose()?
                        .into_iter()
                        .collect(),
                )?;
                match fork {
                    ForkName::Deneb => Self::Deneb(SszForkchoiceUpdateDeneb {
                        forkchoice_state,
                        payload_attributes,
                    }),
                    ForkName::Electra => Self::Electra(SszForkchoiceUpdateElectra {
                        forkchoice_state,
                        payload_attributes,
                    }),
                    _ => Self::Fulu(SszForkchoiceUpdateFulu {
                        forkchoice_state,
                        payload_attributes,
                    }),
                }
            }
            other => {
                return Err(Error::UnsupportedForkVariant(format!(
                    "no pre-Amsterdam forkchoice update for {other}"
                )));
            }
        };
        Ok(update)
    }
}

impl<E: EthSpec> SszForkchoiceUpdateAmsterdam<E> {
    pub fn new(
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
        custody_columns: Option<BitVector<E::CellsPerExtBlob>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            forkchoice_state,
            payload_attributes: VariableList::new(
                payload_attributes
                    .map(|attributes| attributes.as_v4().cloned())
                    .transpose()?
                    .into_iter()
                    .collect(),
            )?,
            custody_columns: VariableList::new(custody_columns.into_iter().collect())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszForkchoiceUpdatedResponse<E: EthSpec> {
    pub payload_status: SszPayloadStatusV1<E>,
    pub payload_id: VariableList<PayloadId, U1>,
}

impl<E: EthSpec> TryFrom<SszForkchoiceUpdatedResponse<E>> for ForkchoiceUpdatedResponse {
    type Error = String;

    fn try_from(value: SszForkchoiceUpdatedResponse<E>) -> Result<Self, Self::Error> {
        Ok(Self {
            payload_status: PayloadStatusV1::try_from(value.payload_status)?,
            payload_id: value.payload_id.first().copied(),
        })
    }
}

impl<E: EthSpec> TryFrom<ForkchoiceUpdatedResponse> for SszForkchoiceUpdatedResponse<E> {
    type Error = ssz_types::Error;

    fn try_from(value: ForkchoiceUpdatedResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            payload_status: SszPayloadStatusV1::try_from(value.payload_status)?,
            payload_id: VariableList::new(value.payload_id.into_iter().collect())?,
        })
    }
}

#[superstruct(
    variants(V1, V2),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszBlobsRequest<E: EthSpec> {
    pub versioned_hashes: VariableList<Hash256, E::MaxVersionedHashesPerRequest>,
    #[superstruct(only(V2))]
    pub indices_bitarray: BitVector<E::CellsPerExtBlob>,
}

impl<E: EthSpec> SszBlobsRequest<E> {
    pub fn new_blobs_request_v1(
        versioned_hashes: Vec<Hash256>,
    ) -> Result<SszBlobsRequestV1<E>, ssz_types::Error> {
        Ok(SszBlobsRequestV1 {
            versioned_hashes: VariableList::new(versioned_hashes)?,
        })
    }

    pub fn new_blobs_request_v2(
        versioned_hashes: Vec<Hash256>,
        indices_bitarray: BitVector<E::CellsPerExtBlob>,
    ) -> Result<SszBlobsRequestV2<E>, ssz_types::Error> {
        Ok(SszBlobsRequestV2 {
            versioned_hashes: VariableList::new(versioned_hashes)?,
            indices_bitarray,
        })
    }
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub struct BlobsEntry<E: EthSpec> {
    pub available: bool,
    pub contents: BlobAndProofV2<E>,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub struct SszBlobsResponse<E: EthSpec> {
    pub entries: VariableList<BlobsEntry<E>, E::MaxVersionedHashesPerRequest>,
}

impl<E: EthSpec> SszBlobsResponse<E> {
    /// `/blobs/v2` (all-or-nothing): a miss is a `204`, so every entry in a `200` body is present.
    pub fn into_v2(self) -> Vec<BlobAndProofV2<E>> {
        self.entries
            .into_iter()
            .map(|entry| entry.contents)
            .collect()
    }

    /// `/blobs/v3` (partial): `available == false` → zero-valued contents ignored → `None`.
    pub fn into_v3(self) -> Vec<BlobAndProofV3<E>> {
        self.entries
            .into_iter()
            .map(|entry| entry.available.then_some(entry.contents))
            .collect()
    }
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub struct SszBodiesByHashRequest {
    pub block_hashes: VariableList<Hash256, U32>,
}

impl SszBodiesByHashRequest {
    pub fn new(block_hashes: Vec<Hash256>) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            block_hashes: VariableList::new(block_hashes)?,
        })
    }
}

/// SSZ `BodyEntry`. `V1` = Paris (Bellatrix), `V2` = Shanghai..Osaka (Capella..Fulu),
/// `V3` = Amsterdam (Gloas) — the `body` variant tracks the fork's body schema.
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszBodyEntry<E: EthSpec> {
    pub available: bool,
    #[superstruct(only(V1), partial_getter(rename = "body_v1"))]
    pub body: SszExecutionPayloadBodyV1<E>,
    #[superstruct(only(V2), partial_getter(rename = "body_v2"))]
    pub body: SszExecutionPayloadBodyV2<E>,
    #[superstruct(only(V3), partial_getter(rename = "body_v3"))]
    pub body: SszExecutionPayloadBodyV3<E>,
}

/// SSZ `BodiesResponse` for `engine_getPayloadBodiesBy{Hash,Range}`.
///
/// The response is fork-homogeneous: every entry is serialised against the fork
/// named by the `Eth-Execution-Version` request header, so the variant is known
/// from the request and is never inferred from the bytes (see `from_ssz_bytes_by_fork`).
// `U32` == `MAX_BODIES_REQUEST` (32).
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "transparent")]
pub struct SszBodiesResponse<E: EthSpec> {
    #[superstruct(only(V1), partial_getter(rename = "entries_v1"))]
    pub entries: VariableList<SszBodyEntryV1<E>, U32>,
    #[superstruct(only(V2), partial_getter(rename = "entries_v2"))]
    pub entries: VariableList<SszBodyEntryV2<E>, U32>,
    #[superstruct(only(V3), partial_getter(rename = "entries_v3"))]
    pub entries: VariableList<SszBodyEntryV3<E>, U32>,
}

impl<E: EthSpec> SszBodiesResponse<E> {
    pub fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(DecodeError::BytesInvalid(format!(
                "unsupported fork for execution payload bodies: {fork_name}"
            ))),
            ForkName::Bellatrix => SszBodiesResponseV1::from_ssz_bytes(bytes).map(Self::V1),
            ForkName::Capella | ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
                SszBodiesResponseV2::from_ssz_bytes(bytes).map(Self::V2)
            }
            ForkName::Gloas => SszBodiesResponseV3::from_ssz_bytes(bytes).map(Self::V3),
        }
    }

    pub fn into_bodies(self) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, String> {
        match self {
            Self::V1(resp) => Ok(resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV1::from(entry.body))
                })
                .collect()),
            Self::V2(resp) => Ok(resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV1::from(entry.body))
                })
                .collect()),
            Self::V3(resp) => Ok(resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV1::from(entry.body))
                })
                .collect())
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SszLimits {
    pub bodies_max_count: Option<u64>,
    pub blobs_max_versioned_hashes: Option<u64>,
    pub payload_max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SszCapabilities {
    pub supported_forks: HashSet<ForkName>,
    pub payloads: bool,
    pub forkchoice: bool,
    pub bodies: bool,
    pub blobs_v1: bool,
    pub blobs_v2: bool,
    pub blobs_v3: bool,
    pub blobs_v4: bool,
    pub unscoped_endpoints: Vec<String>,
    pub limits: SszLimits,
}

impl SszCapabilities {
    pub fn new_payload(&self, fork: ForkName) -> bool {
        self.supported_forks.contains(&fork) && self.payloads
    }

    pub fn get_payload(&self, fork: ForkName) -> bool {
        self.supported_forks.contains(&fork) && self.payloads
    }

    pub fn forkchoice_updated(&self, fork: ForkName) -> bool {
        self.supported_forks.contains(&fork) && self.forkchoice
    }

    pub fn get_payload_bodies(&self, fork: ForkName) -> bool {
        self.supported_forks.contains(&fork) && self.bodies
    }

    pub fn get_blobs_v2(&self) -> bool {
        self.blobs_v2
    }

    pub fn get_blobs_v3(&self) -> bool {
        self.blobs_v3
    }

    pub fn get_client_version_v1(&self) -> bool {
        self.unscoped_endpoints
            .iter()
            .any(|endpoint| endpoint == "identity")
    }

    pub fn highest_supported_fork(&self) -> Option<ForkName> {
        self.supported_forks.iter().copied().max()
    }
}

#[derive(Deserialize)]
pub struct JsonCapabilities {
    #[serde(default)]
    supported_forks: Vec<String>,
    #[serde(default)]
    fork_scoped_endpoints: Vec<String>,
    #[serde(default)]
    independently_versioned: JsonIndependentlyVersioned,
    #[serde(default)]
    unscoped_endpoints: Vec<String>,
    #[serde(default)]
    limits: JsonLimits,
}

#[derive(Deserialize, Default)]
struct JsonIndependentlyVersioned {
    #[serde(default)]
    blobs: Vec<String>,
}

#[derive(Deserialize, Default)]
struct JsonLimits {
    #[serde(rename = "bodies.max_count")]
    bodies_max_count: Option<u64>,
    #[serde(rename = "blobs.max_versioned_hashes")]
    blobs_max_versioned_hashes: Option<u64>,
    #[serde(rename = "payload.max_bytes")]
    payload_max_bytes: Option<u64>,
}

fn fork_from_header(header: &str) -> Option<ForkName> {
    Some(match header {
        "paris" => ForkName::Bellatrix,
        "shanghai" => ForkName::Capella,
        "cancun" => ForkName::Deneb,
        "prague" => ForkName::Electra,
        "osaka" => ForkName::Fulu,
        "amsterdam" => ForkName::Gloas,
        _ => return None,
    })
}

impl From<JsonCapabilities> for SszCapabilities {
    fn from(capabilities: JsonCapabilities) -> Self {
        let supported_forks = capabilities
            .supported_forks
            .iter()
            .filter_map(|fork| fork_from_header(fork))
            .collect();
        let endpoint = |name: &str| capabilities.fork_scoped_endpoints.iter().any(|e| e == name);
        let blob = |rev: &str| {
            capabilities
                .independently_versioned
                .blobs
                .iter()
                .any(|b| b == rev)
        };
        SszCapabilities {
            supported_forks,
            payloads: endpoint("payloads"),
            forkchoice: endpoint("forkchoice"),
            bodies: endpoint("bodies"),
            blobs_v1: blob("v1"),
            blobs_v2: blob("v2"),
            blobs_v3: blob("v3"),
            blobs_v4: blob("v4"),
            unscoped_endpoints: capabilities.unscoped_endpoints,
            limits: SszLimits {
                bodies_max_count: capabilities.limits.bodies_max_count,
                blobs_max_versioned_hashes: capabilities.limits.blobs_max_versioned_hashes,
                payload_max_bytes: capabilities.limits.payload_max_bytes,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bls::{PublicKeyBytes, SignatureBytes};
    use ssz::Encode;
    use types::{
        Address, BuilderDepositRequest, BuilderExitRequest, ConsolidationRequest, DepositRequest,
        Hash256, MainnetEthSpec, WithdrawalRequest,
    };

    type E = MainnetEthSpec;

    fn deposit_request() -> DepositRequest {
        DepositRequest {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::repeat_byte(1),
            amount: 32,
            signature: SignatureBytes::empty(),
            index: 3,
        }
    }

    fn withdrawal_request() -> WithdrawalRequest {
        WithdrawalRequest {
            source_address: Address::repeat_byte(2),
            validator_pubkey: PublicKeyBytes::empty(),
            amount: 33,
        }
    }

    fn consolidation_request() -> ConsolidationRequest {
        ConsolidationRequest {
            source_address: Address::repeat_byte(3),
            source_pubkey: PublicKeyBytes::empty(),
            target_pubkey: PublicKeyBytes::empty(),
        }
    }

    fn electra_requests() -> ExecutionRequestsElectra<E> {
        ExecutionRequestsElectra {
            deposits: VariableList::new(vec![deposit_request()]).unwrap(),
            withdrawals: VariableList::new(vec![withdrawal_request()]).unwrap(),
            consolidations: VariableList::new(vec![consolidation_request()]).unwrap(),
        }
    }

    #[test]
    fn fulu_new_payload_envelope_folds_requests_and_drops_versioned_hashes() {
        let payload = ExecutionPayloadFulu::<E>::default();
        let requests = electra_requests();
        let parent_beacon_block_root = Hash256::repeat_byte(9);

        let request = NewPayloadRequestFulu {
            execution_payload: &payload,
            versioned_hashes: vec![Hash256::repeat_byte(1), Hash256::repeat_byte(2)],
            parent_beacon_block_root,
            execution_requests: &requests,
        };

        let envelope = SszExecutionPayloadEnvelopeFulu::try_from(request).unwrap();
        let decoded =
            SszExecutionPayloadEnvelopeFulu::<E>::from_ssz_bytes(&envelope.as_ssz_bytes()).unwrap();

        assert_eq!(decoded.parent_beacon_block_root, parent_beacon_block_root);
        assert_eq!(decoded.execution_payload, payload);
        assert_eq!(
            execution_requests_electra_from_ssz(decoded.execution_requests).unwrap(),
            requests
        );
    }

    #[test]
    fn gloas_new_payload_envelope_folds_builder_requests() {
        let payload = ExecutionPayloadGloas::<E>::default();
        let requests = ExecutionRequestsGloas {
            deposits: VariableList::new(vec![deposit_request()]).unwrap(),
            withdrawals: VariableList::new(vec![withdrawal_request()]).unwrap(),
            consolidations: VariableList::new(vec![consolidation_request()]).unwrap(),
            builder_deposits: VariableList::new(vec![BuilderDepositRequest {
                pubkey: PublicKeyBytes::empty(),
                withdrawal_credentials: Hash256::repeat_byte(4),
                amount: 34,
                signature: SignatureBytes::empty(),
            }])
            .unwrap(),
            builder_exits: VariableList::new(vec![BuilderExitRequest {
                source_address: Address::repeat_byte(5),
                pubkey: PublicKeyBytes::empty(),
            }])
            .unwrap(),
        };
        let parent_beacon_block_root = Hash256::repeat_byte(9);

        let request = NewPayloadRequestGloas {
            execution_payload: &payload,
            versioned_hashes: vec![Hash256::repeat_byte(1)],
            parent_beacon_block_root,
            execution_requests: &requests,
        };

        let envelope = SszExecutionPayloadEnvelopeGloas::try_from(request).unwrap();
        let decoded =
            SszExecutionPayloadEnvelopeGloas::<E>::from_ssz_bytes(&envelope.as_ssz_bytes()).unwrap();

        assert_eq!(decoded.parent_beacon_block_root, parent_beacon_block_root);
        assert_eq!(
            execution_requests_gloas_from_ssz(decoded.execution_requests).unwrap(),
            requests
        );
    }
}
