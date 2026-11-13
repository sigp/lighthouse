use crate::json_structures::{BlobAndProofV2, BlobAndProofV3};

use super::json_structures::{
    BlobCellsAndProofsV1, CustodyColumnsBitArray, GetBlobsV4List, JsonCell, RequestsError,
    parse_execution_requests_bytes,
};
use super::*;
use serde::Deserialize;
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitVector, ProgressiveVariableList, VariableList};
use std::collections::HashSet;
use superstruct::superstruct;
use typenum::{U1, U32, U128, U256, U1024};
use types::data::Cell;
use types::execution::{ExecutionRequestsElectra, ExecutionRequestsGloas};
use types::{EthSpec, KzgProof, ProgressiveTransactions, Transactions};
use types::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas, ExecutionPayloadHeze,
    ExecutionRequests, ForkName,
};

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct SszExecutionPayloadBody<E: EthSpec> {
    pub transactions: Transactions<E>,
    #[superstruct(only(V2, V3))]
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(V3))]
    pub block_access_list: VariableList<u8, E::MaxBytesPerTransaction>,
}

// SszExecutionPayloadBodyV1 <-> ExecutionPayloadBodyV1

impl<E: EthSpec> From<SszExecutionPayloadBodyV1<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: SszExecutionPayloadBodyV1<E>) -> Self {
        Self {
            transactions: value.transactions,
            withdrawals: None,
        }
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV1<E>> for SszExecutionPayloadBodyV1<E> {
    type Error = Error;

    fn try_from(value: ExecutionPayloadBodyV1<E>) -> Result<Self, Self::Error> {
        if value.withdrawals.is_some() {
            return Err(Error::UnsupportedForkVariant(
                "withdrawals in a Paris (V1) body".to_string(),
            ));
        }

        Ok(Self {
            transactions: value.transactions,
        })
    }
}

// SszExecutionPayloadBodyV2 <-> ExecutionPayloadBodyV1

impl<E: EthSpec> From<SszExecutionPayloadBodyV2<E>> for ExecutionPayloadBodyV1<E> {
    fn from(value: SszExecutionPayloadBodyV2<E>) -> Self {
        Self {
            transactions: value.transactions,
            withdrawals: Some(value.withdrawals),
        }
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV1<E>> for SszExecutionPayloadBodyV2<E> {
    type Error = Error;

    fn try_from(value: ExecutionPayloadBodyV1<E>) -> Result<Self, Self::Error> {
        Ok(Self {
            transactions: value.transactions,
            withdrawals: value.withdrawals.ok_or_else(|| {
                Error::UnsupportedForkVariant("no withdrawals for a Shanghai (V2) body".to_string())
            })?,
        })
    }
}

// SszExecutionPayloadBodyV1 <-> ExecutionPayloadBodyV2

/// Repackage the bounded SSZ wire transactions into the progressive (Gloas) container.
fn progressive_transactions_from_wire<E: EthSpec>(
    transactions: Transactions<E>,
) -> Result<ProgressiveTransactions, ssz_types::Error> {
    transactions
        .into_iter()
        .map(|transaction| ProgressiveVariableList::new(transaction.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(ProgressiveVariableList::new)
}

fn wire_transactions_from_progressive<E: EthSpec>(
    transactions: ProgressiveTransactions,
) -> Result<Transactions<E>, ssz_types::Error> {
    transactions
        .into_iter()
        .map(|transaction| VariableList::new(transaction.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(VariableList::new)
}

impl<E: EthSpec> TryFrom<SszExecutionPayloadBodyV1<E>> for ExecutionPayloadBodyV2<E> {
    type Error = ssz_types::Error;

    fn try_from(value: SszExecutionPayloadBodyV1<E>) -> Result<Self, Self::Error> {
        Ok(Self {
            transactions: progressive_transactions_from_wire::<E>(value.transactions)?,
            withdrawals: None,
            block_access_list: None,
        })
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV2<E>> for SszExecutionPayloadBodyV1<E> {
    type Error = Error;

    fn try_from(value: ExecutionPayloadBodyV2<E>) -> Result<Self, Self::Error> {
        if value.withdrawals.is_some() || value.block_access_list.is_some() {
            return Err(Error::UnsupportedForkVariant(
                "withdrawals or block access list in a Paris (V1) body".to_string(),
            ));
        }

        Ok(Self {
            transactions: wire_transactions_from_progressive::<E>(value.transactions)?,
        })
    }
}

// SszExecutionPayloadBodyV2 <-> ExecutionPayloadBodyV2

impl<E: EthSpec> TryFrom<SszExecutionPayloadBodyV2<E>> for ExecutionPayloadBodyV2<E> {
    type Error = ssz_types::Error;

    fn try_from(value: SszExecutionPayloadBodyV2<E>) -> Result<Self, Self::Error> {
        let withdrawals = ProgressiveVariableList::new(value.withdrawals.to_vec())?;
        Ok(Self {
            transactions: progressive_transactions_from_wire::<E>(value.transactions)?,
            withdrawals: Some(withdrawals),
            block_access_list: None,
        })
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV2<E>> for SszExecutionPayloadBodyV2<E> {
    type Error = Error;

    fn try_from(value: ExecutionPayloadBodyV2<E>) -> Result<Self, Self::Error> {
        if value.block_access_list.is_some() {
            return Err(Error::UnsupportedForkVariant(
                "block access list in a Shanghai (V2) body".to_string(),
            ));
        }
        let withdrawals = value.withdrawals.ok_or_else(|| {
            Error::UnsupportedForkVariant("no withdrawals for a Shanghai (V2) body".to_string())
        })?;

        Ok(Self {
            transactions: wire_transactions_from_progressive::<E>(value.transactions)?,
            withdrawals: VariableList::new(withdrawals.to_vec())?,
        })
    }
}

// SszExecutionPayloadBodyV3 <-> ExecutionPayloadBodyV2

impl<E: EthSpec> TryFrom<SszExecutionPayloadBodyV3<E>> for ExecutionPayloadBodyV2<E> {
    type Error = ssz_types::Error;

    fn try_from(value: SszExecutionPayloadBodyV3<E>) -> Result<Self, Self::Error> {
        let withdrawals = ProgressiveVariableList::new(value.withdrawals.to_vec())?;
        let block_access_list = ProgressiveVariableList::new(value.block_access_list.to_vec())?;
        Ok(Self {
            transactions: progressive_transactions_from_wire::<E>(value.transactions)?,
            withdrawals: Some(withdrawals),
            block_access_list: Some(block_access_list),
        })
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadBodyV2<E>> for SszExecutionPayloadBodyV3<E> {
    type Error = Error;

    fn try_from(value: ExecutionPayloadBodyV2<E>) -> Result<Self, Self::Error> {
        let withdrawals = value.withdrawals.ok_or_else(|| {
            Error::UnsupportedForkVariant("no withdrawals for an Amsterdam (V3) body".to_string())
        })?;
        let block_access_list = value.block_access_list.ok_or_else(|| {
            Error::UnsupportedForkVariant(
                "no block access list for an Amsterdam (V3) body".to_string(),
            )
        })?;

        // Repackage the unbounded progressive containers into the bounded wire lists, surfacing
        // any element that overflows an SSZ length bound as an error.
        Ok(Self {
            transactions: wire_transactions_from_progressive::<E>(value.transactions)?,
            withdrawals: VariableList::new(withdrawals.to_vec())?,
            block_access_list: VariableList::new(block_access_list.to_vec())?,
        })
    }
}

type SszExecutionRequests<E> = VariableList<
    VariableList<u8, <E as EthSpec>::MaxBytesPerTransaction>,
    MaxExecutionRequestsPerPayload,
>;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas, Heze),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    map_into(ExecutionPayload),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
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
    #[superstruct(only(Heze), partial_getter(rename = "execution_payload_heze"))]
    pub execution_payload: ExecutionPayloadHeze<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas, Heze))]
    pub parent_beacon_block_root: Hash256,
    #[superstruct(only(Electra, Fulu, Gloas, Heze))]
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

impl<'block, E: EthSpec> TryFrom<NewPayloadRequestHeze<'block, E>>
    for SszExecutionPayloadEnvelopeHeze<E>
{
    type Error = ssz_types::Error;
    fn try_from(value: NewPayloadRequestHeze<'block, E>) -> Result<Self, Self::Error> {
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

/// Parse an EIP-7685 SSZ requests list using the request types for the fork.
///
/// The elements are already raw `request_type ++ request_data` bytes, so this calls the shared
/// byte-level parser directly, without the hex step the JSON path needs.
fn parse_execution_requests_ssz<E: EthSpec>(
    ssz_requests: &SszExecutionRequests<E>,
    fork_name: ForkName,
) -> Result<ExecutionRequests<E>, RequestsError> {
    parse_execution_requests_bytes(
        ssz_requests.iter().map(|request| Ok::<&[u8], _>(request)),
        fork_name,
    )
}

fn execution_requests_electra_from_ssz<E: EthSpec>(
    ssz_requests: SszExecutionRequests<E>,
) -> Result<ExecutionRequestsElectra<E>, RequestsError> {
    match parse_execution_requests_ssz(&ssz_requests, ForkName::Electra)? {
        ExecutionRequests::Electra(requests) => Ok(requests),
        ExecutionRequests::Gloas(_) => Err(RequestsError::VariantMismatch),
    }
}

fn execution_requests_gloas_from_ssz<E: EthSpec>(
    ssz_requests: SszExecutionRequests<E>,
) -> Result<ExecutionRequestsGloas<E>, RequestsError> {
    match parse_execution_requests_ssz(&ssz_requests, ForkName::Gloas)? {
        ExecutionRequests::Gloas(requests) => Ok(requests),
        ExecutionRequests::Electra(_) => Err(RequestsError::VariantMismatch),
    }
}

#[derive(Debug, PartialEq, Encode, Decode)]
pub struct SszPayloadStatusV1 {
    pub payload_status: u8,
    pub latest_valid_hash: VariableList<Hash256, U1>,
    pub validation_error: VariableList<VariableList<u8, MaxErrorBytes>, U1>,
}

impl TryFrom<SszPayloadStatusV1> for PayloadStatusV1 {
    type Error = Error;

    fn try_from(value: SszPayloadStatusV1) -> Result<Self, Self::Error> {
        let status = match value.payload_status {
            0 => PayloadStatusV1Status::Valid,
            1 => PayloadStatusV1Status::Invalid,
            2 => PayloadStatusV1Status::Syncing,
            3 => PayloadStatusV1Status::Accepted,
            other => {
                return Err(Error::BadResponse(format!(
                    "invalid payload status {other} from EL"
                )));
            }
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
            inclusion_list_satisfied: None,
        })
    }
}

impl TryFrom<PayloadStatusV1> for SszPayloadStatusV1 {
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
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas, Heze),
    variant_attributes(derive(Debug, PartialEq, Encode, Decode),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq)]
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
    #[superstruct(only(Heze), partial_getter(rename = "execution_payload_heze"))]
    pub execution_payload: ExecutionPayloadHeze<E>,
    pub block_value: Uint256,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas, Heze))]
    pub blobs_bundle: BlobsBundle<E>,
    #[superstruct(only(Electra, Fulu, Gloas, Heze))]
    pub requests: SszExecutionRequests<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas, Heze), partial_getter(copy))]
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
            ForkName::Heze => SszGetPayloadResponseHeze::from_ssz_bytes(bytes).map(Self::Heze),
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
            SszGetPayloadResponse::Heze(response) => {
                Ok(GetPayloadResponse::Heze(GetPayloadResponseHeze {
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

impl<E: EthSpec> TryFrom<GetPayloadResponse<E>> for SszGetPayloadResponse<E> {
    type Error = ssz_types::Error;

    fn try_from(value: GetPayloadResponse<E>) -> Result<Self, Self::Error> {
        match value {
            GetPayloadResponse::Bellatrix(response) => Ok(SszGetPayloadResponse::Bellatrix(
                SszGetPayloadResponseBellatrix {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                },
            )),
            GetPayloadResponse::Capella(response) => Ok(SszGetPayloadResponse::Capella(
                SszGetPayloadResponseCapella {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                },
            )),
            GetPayloadResponse::Deneb(response) => {
                Ok(SszGetPayloadResponse::Deneb(SszGetPayloadResponseDeneb {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    should_override_builder: response.should_override_builder,
                }))
            }
            GetPayloadResponse::Electra(response) => Ok(SszGetPayloadResponse::Electra(
                SszGetPayloadResponseElectra {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    requests: execution_requests_to_ssz(ExecutionRequests::Electra(
                        response.requests,
                    ))?,
                    should_override_builder: response.should_override_builder,
                },
            )),
            GetPayloadResponse::Fulu(response) => {
                Ok(SszGetPayloadResponse::Fulu(SszGetPayloadResponseFulu {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    requests: execution_requests_to_ssz(ExecutionRequests::Electra(
                        response.requests,
                    ))?,
                    should_override_builder: response.should_override_builder,
                }))
            }
            GetPayloadResponse::Gloas(response) => {
                Ok(SszGetPayloadResponse::Gloas(SszGetPayloadResponseGloas {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    requests: execution_requests_to_ssz(ExecutionRequests::Gloas(
                        response.requests,
                    ))?,
                    should_override_builder: response.should_override_builder,
                }))
            }
            GetPayloadResponse::Heze(response) => {
                Ok(SszGetPayloadResponse::Heze(SszGetPayloadResponseHeze {
                    execution_payload: response.execution_payload,
                    block_value: response.block_value,
                    blobs_bundle: response.blobs_bundle,
                    requests: execution_requests_to_ssz(ExecutionRequests::Gloas(
                        response.requests,
                    ))?,
                    should_override_builder: response.should_override_builder,
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
#[derive(Clone, Debug, PartialEq)]
pub struct SszForkchoiceUpdate {
    pub forkchoice_state: ForkchoiceState,
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "payload_attributes_bellatrix")
    )]
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

/// Amsterdam SSZ `engine_forkchoiceUpdated` request body (adds `custody_columns`).
#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct SszForkchoiceUpdateCustodyColumns<E: EthSpec> {
    pub forkchoice_state: ForkchoiceState,
    #[superstruct(only(Gloas), partial_getter(rename = "payload_attributes_gloas"))]
    pub payload_attributes: VariableList<PayloadAttributesV4, U1>,
    #[superstruct(only(Heze), partial_getter(rename = "payload_attributes_heze"))]
    pub payload_attributes: VariableList<PayloadAttributesV5, U1>,
    #[superstruct(only(Gloas, Heze))]
    pub custody_columns: VariableList<BitVector<E::CellsPerExtBlob>, U1>,
}

impl<E: EthSpec> SszForkchoiceUpdateCustodyColumns<E> {
    pub fn new(
        fork: ForkName,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
        custody_columns: Option<CustodyColumnsBitArray>,
    ) -> Result<Self, Error> {
        let custody_columns: Option<BitVector<E::CellsPerExtBlob>> =
            if let Some(bit_array) = custody_columns {
                Some(custody_columns_to_bit_vector::<E>(bit_array)?)
            } else {
                None
            };
        let update = match fork {
            ForkName::Gloas => {
                let payload_attributes = VariableList::new(
                    payload_attributes
                        .map(|attributes| attributes.as_v4().cloned())
                        .transpose()?
                        .into_iter()
                        .collect(),
                )?;

                Self::Gloas(SszForkchoiceUpdateCustodyColumnsGloas {
                    forkchoice_state,
                    payload_attributes,
                    custody_columns: VariableList::new(custody_columns.into_iter().collect())?,
                })
            }
            ForkName::Heze => {
                let payload_attributes = VariableList::new(
                    payload_attributes
                        .map(|attributes| attributes.as_v5().cloned())
                        .transpose()?
                        .into_iter()
                        .collect(),
                )?;

                Self::Heze(SszForkchoiceUpdateCustodyColumnsHeze {
                    forkchoice_state,
                    payload_attributes,
                    custody_columns: VariableList::new(custody_columns.into_iter().collect())?,
                })
            }
            other => {
                return Err(Error::UnsupportedForkVariant(format!(
                    "no post-Amsterdam forkchoice update for {other}"
                )));
            }
        };
        Ok(update)
    }
}

#[derive(Debug, PartialEq, Encode, Decode)]
pub struct SszForkchoiceUpdatedResponse {
    pub payload_status: SszPayloadStatusV1,
    pub payload_id: VariableList<PayloadId, U1>,
}

impl TryFrom<SszForkchoiceUpdatedResponse> for ForkchoiceUpdatedResponse {
    type Error = Error;

    fn try_from(value: SszForkchoiceUpdatedResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            payload_status: PayloadStatusV1::try_from(value.payload_status)?,
            payload_id: value.payload_id.first().copied(),
        })
    }
}

impl TryFrom<ForkchoiceUpdatedResponse> for SszForkchoiceUpdatedResponse {
    type Error = ssz_types::Error;

    fn try_from(value: ForkchoiceUpdatedResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            payload_status: SszPayloadStatusV1::try_from(value.payload_status)?,
            payload_id: VariableList::new(value.payload_id.into_iter().collect())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct SszBlobsRequestV1 {
    pub versioned_hashes: VariableList<Hash256, MaxVersionedHashesPerRequest>,
}

impl SszBlobsRequestV1 {
    pub fn new(versioned_hashes: Vec<Hash256>) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            versioned_hashes: VariableList::new(versioned_hashes)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct SszBlobsRequestV2<E: EthSpec> {
    pub versioned_hashes: VariableList<Hash256, MaxVersionedHashesPerRequest>,
    pub indices_bitarray: BitVector<E::CellsPerExtBlob>,
}

impl<E: EthSpec> SszBlobsRequestV2<E> {
    pub fn new(
        versioned_hashes: Vec<Hash256>,
        indices_bitarray: CustodyColumnsBitArray,
    ) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            versioned_hashes: VariableList::new(versioned_hashes)?,
            indices_bitarray: custody_columns_to_bit_vector::<E>(indices_bitarray)?,
        })
    }
}

#[superstruct(
    variants(V2, V4),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct BlobsEntry<E: EthSpec> {
    pub available: bool,
    #[superstruct(only(V2), partial_getter(rename = "contents_v2"))]
    pub contents: BlobAndProofV2<E>,
    #[superstruct(only(V4), partial_getter(rename = "contents_v4"))]
    pub contents: SszBlobCellsAndProofs<E>,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub struct SszBlobCellsAndProofs<E: EthSpec> {
    pub blob_cells: VariableList<VariableList<Cell<E>, U1>, E::CellsPerExtBlob>,
    pub proofs: VariableList<VariableList<KzgProof, U1>, E::CellsPerExtBlob>,
}

impl<E: EthSpec> From<SszBlobCellsAndProofs<E>> for BlobCellsAndProofsV1<E> {
    fn from(value: SszBlobCellsAndProofs<E>) -> Self {
        Self {
            blob_cells: value
                .blob_cells
                .into_iter()
                .map(|cell| cell.into_iter().next().map(JsonCell))
                .collect(),
            proofs: value
                .proofs
                .into_iter()
                .map(|proof| proof.into_iter().next())
                .collect(),
        }
    }
}

impl<E: EthSpec> TryFrom<BlobCellsAndProofsV1<E>> for SszBlobCellsAndProofs<E> {
    type Error = ssz_types::Error;

    fn try_from(value: BlobCellsAndProofsV1<E>) -> Result<Self, ssz_types::Error> {
        let blob_cells = value
            .blob_cells
            .into_iter()
            .map(|cell| VariableList::new(cell.map(|json_cell| json_cell.0).into_iter().collect()))
            .collect::<Result<Vec<_>, _>>()?;
        let proofs = value
            .proofs
            .into_iter()
            .map(|proof| VariableList::new(proof.into_iter().collect()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            blob_cells: VariableList::new(blob_cells)?,
            proofs: VariableList::new(proofs)?,
        })
    }
}

#[superstruct(
    variants(V2, V4),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct SszBlobsResponse<E: EthSpec> {
    #[superstruct(only(V2), partial_getter(rename = "entries_v2"))]
    pub entries: VariableList<BlobsEntryV2<E>, MaxVersionedHashesPerRequest>,
    #[superstruct(only(V4), partial_getter(rename = "entries_v4"))]
    pub entries: VariableList<BlobsEntryV4<E>, MaxVersionedHashesPerRequest>,
}

impl<E: EthSpec> SszBlobsResponseV2<E> {
    /// `/blobs/v2` is all-or-nothing: a miss is a `204`, so every entry in a `200` body must be
    /// available. An unavailable entry is rejected rather than returned as a zero-valued blob.
    pub fn into_v2(self) -> Result<Vec<BlobAndProofV2<E>>, Error> {
        self.entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                if entry.available {
                    Ok(entry.contents)
                } else {
                    Err(Error::BadResponse(format!(
                        "blobs/v2 entry {index} is not available in a 200 response"
                    )))
                }
            })
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

impl<E: EthSpec> SszBlobsResponseV4<E> {
    /// `/blobs/v4` (partial): `available == false` → `None`; else the cell/proof contents,
    /// converted to the transport-neutral `BlobCellsAndProofsV1`.
    pub fn into_v4(self) -> GetBlobsV4List<E> {
        self.entries
            .into_iter()
            .map(|entry| entry.available.then(|| entry.contents.into()))
            .collect()
    }
}

pub type MaxBodiesRequest = U32;
pub type MaxVersionedHashesPerRequest = U128;
pub type MaxExecutionRequestsPerPayload = U256;
pub type MaxErrorBytes = U1024;

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub struct SszBodiesByHashRequest {
    pub block_hashes: VariableList<Hash256, MaxBodiesRequest>,
}

impl SszBodiesByHashRequest {
    pub fn new(block_hashes: Vec<Hash256>) -> Result<Self, ssz_types::Error> {
        Ok(Self {
            block_hashes: VariableList::new(block_hashes)?,
        })
    }
}

/// SSZ `BodyEntry`. `V1` = Paris (Bellatrix), `V2` = Shanghai..Osaka (Capella..Fulu),
/// `V3` = Amsterdam (Gloas), Bogota (Heze) — the `body` variant tracks the fork's body schema.
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct SszBodyEntry<E: EthSpec> {
    pub available: bool,
    #[superstruct(only(V1), partial_getter(rename = "body_v1"))]
    pub body: SszExecutionPayloadBodyV1<E>,
    #[superstruct(only(V2), partial_getter(rename = "body_v2"))]
    pub body: SszExecutionPayloadBodyV2<E>,
    #[superstruct(only(V3), partial_getter(rename = "body_v3"))]
    pub body: SszExecutionPayloadBodyV3<E>,
}

/// SSZ `BodiesResponse` for `engine_getPayloadBodiesByHash`.
///
/// The response is fork-homogeneous: every entry is serialised against the fork
/// named by the `Eth-Execution-Version` request header, so the variant is known
/// from the request and is never inferred from the bytes (see `from_ssz_bytes_by_fork`).
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Encode, Decode, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct SszBodiesResponse<E: EthSpec> {
    #[superstruct(only(V1), partial_getter(rename = "entries_v1"))]
    pub entries: VariableList<SszBodyEntryV1<E>, MaxBodiesRequest>,
    #[superstruct(only(V2), partial_getter(rename = "entries_v2"))]
    pub entries: VariableList<SszBodyEntryV2<E>, MaxBodiesRequest>,
    #[superstruct(only(V3), partial_getter(rename = "entries_v3"))]
    pub entries: VariableList<SszBodyEntryV3<E>, MaxBodiesRequest>,
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
            ForkName::Gloas | ForkName::Heze => {
                SszBodiesResponseV3::from_ssz_bytes(bytes).map(Self::V3)
            }
        }
    }

    pub fn into_bodies(self) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
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
            Self::V3(_) => Err(Error::UnsupportedForkVariant(
                "V3 bodies have no ExecutionPayloadBodyV1 form, use into_bodies_v2".to_string(),
            )),
        }
    }

    pub fn into_bodies_v2(
        self,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2<E>>>, ssz_types::Error> {
        match self {
            Self::V1(resp) => resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV2::try_from(entry.body))
                        .transpose()
                })
                .collect(),
            Self::V2(resp) => resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV2::try_from(entry.body))
                        .transpose()
                })
                .collect(),
            Self::V3(resp) => resp
                .entries
                .into_iter()
                .map(|entry| {
                    entry
                        .available
                        .then(|| ExecutionPayloadBodyV2::try_from(entry.body))
                        .transpose()
                })
                .collect(),
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
    pub fn payloads(&self, fork: ForkName) -> bool {
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

    pub fn get_blobs_v4(&self) -> bool {
        self.blobs_v4
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
        "bogota" => ForkName::Heze,
        _ => return None,
    })
}

fn custody_columns_to_bit_vector<E: EthSpec>(
    bit_array: CustodyColumnsBitArray,
) -> Result<BitVector<E::CellsPerExtBlob>, ssz_types::Error> {
    let mut indices = BitVector::<E::CellsPerExtBlob>::new();
    let len = indices.len();
    for column in bit_array.iter_set_bits() {
        let column = column as usize;
        indices
            .set(column, true)
            .map_err(|_| ssz_types::Error::OutOfBounds { i: column, len })?;
    }
    Ok(indices)
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
    use ssz_types::ProgressiveVariableList;
    use types::execution::RequestType;
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
            deposits: ProgressiveVariableList::new(vec![deposit_request()]).unwrap(),
            withdrawals: ProgressiveVariableList::new(vec![withdrawal_request()]).unwrap(),
            consolidations: ProgressiveVariableList::new(vec![consolidation_request()]).unwrap(),
            builder_deposits: ProgressiveVariableList::new(vec![BuilderDepositRequest {
                pubkey: PublicKeyBytes::empty(),
                withdrawal_credentials: Hash256::repeat_byte(4),
                amount: 34,
                signature: SignatureBytes::empty(),
            }])
            .unwrap(),
            builder_exits: ProgressiveVariableList::new(vec![BuilderExitRequest {
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
            SszExecutionPayloadEnvelopeGloas::<E>::from_ssz_bytes(&envelope.as_ssz_bytes())
                .unwrap();

        assert_eq!(decoded.parent_beacon_block_root, parent_beacon_block_root);
        assert_eq!(
            execution_requests_gloas_from_ssz(decoded.execution_requests).unwrap(),
            requests
        );
    }

    fn transactions() -> Transactions<E> {
        VariableList::new(vec![
            VariableList::new(vec![1, 2, 3]).unwrap(),
            VariableList::new(vec![0xff; 4]).unwrap(),
        ])
        .unwrap()
    }

    fn withdrawals() -> Withdrawals<E> {
        VariableList::new(vec![
            Withdrawal {
                index: 7,
                validator_index: 11,
                address: Address::repeat_byte(4),
                amount: 32,
            },
            Withdrawal {
                index: 8,
                validator_index: 12,
                address: Address::repeat_byte(5),
                amount: 33,
            },
        ])
        .unwrap()
    }

    fn progressive_transactions() -> ProgressiveTransactions {
        ProgressiveVariableList::new(
            transactions()
                .iter()
                .map(|transaction| ProgressiveVariableList::new(transaction.to_vec()).unwrap())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn paris_body_v1_round_trips_through_ssz() {
        let body = ExecutionPayloadBodyV1::<E> {
            transactions: transactions(),
            withdrawals: None,
        };

        let ssz_body = SszExecutionPayloadBodyV1::try_from(body.clone()).unwrap();
        let decoded =
            SszExecutionPayloadBodyV1::<E>::from_ssz_bytes(&ssz_body.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, ssz_body);

        let round_tripped = ExecutionPayloadBodyV1::from(decoded);
        assert_eq!(round_tripped.transactions, body.transactions);
        assert!(round_tripped.withdrawals.is_none());
    }

    #[test]
    fn shanghai_body_v2_round_trips_through_ssz() {
        let body = ExecutionPayloadBodyV1::<E> {
            transactions: transactions(),
            withdrawals: Some(withdrawals()),
        };

        let ssz_body = SszExecutionPayloadBodyV2::try_from(body.clone()).unwrap();
        let decoded =
            SszExecutionPayloadBodyV2::<E>::from_ssz_bytes(&ssz_body.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, ssz_body);

        let round_tripped = ExecutionPayloadBodyV1::from(decoded);
        assert_eq!(round_tripped.transactions, body.transactions);
        assert_eq!(round_tripped.withdrawals, body.withdrawals);
    }

    #[test]
    fn amsterdam_body_v3_round_trips_through_ssz() {
        let body = ExecutionPayloadBodyV2::<E> {
            transactions: progressive_transactions(),
            withdrawals: Some(ProgressiveVariableList::new(withdrawals().to_vec()).unwrap()),
            block_access_list: Some(ProgressiveVariableList::new(vec![0xab; 5]).unwrap()),
        };

        let ssz_body = SszExecutionPayloadBodyV3::try_from(body.clone()).unwrap();
        let decoded =
            SszExecutionPayloadBodyV3::<E>::from_ssz_bytes(&ssz_body.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, ssz_body);

        assert_eq!(ExecutionPayloadBodyV2::try_from(decoded).unwrap(), body);
    }

    #[test]
    fn amsterdam_body_v3_rejects_missing_withdrawals() {
        let body = ExecutionPayloadBodyV2::<E> {
            transactions: progressive_transactions(),
            withdrawals: None,
            block_access_list: Some(ProgressiveVariableList::new(vec![0xab; 5]).unwrap()),
        };

        assert!(matches!(
            SszExecutionPayloadBodyV3::try_from(body),
            Err(Error::UnsupportedForkVariant(_))
        ));
    }

    #[test]
    fn amsterdam_body_v3_rejects_missing_block_access_list() {
        let body = ExecutionPayloadBodyV2::<E> {
            transactions: progressive_transactions(),
            withdrawals: Some(ProgressiveVariableList::new(withdrawals().to_vec()).unwrap()),
            block_access_list: None,
        };

        assert!(matches!(
            SszExecutionPayloadBodyV3::try_from(body),
            Err(Error::UnsupportedForkVariant(_))
        ));
    }

    #[test]
    fn paris_body_v1_round_trips_from_body_v2() {
        let body = ExecutionPayloadBodyV2::<E> {
            transactions: progressive_transactions(),
            withdrawals: None,
            block_access_list: None,
        };

        let ssz_body = SszExecutionPayloadBodyV1::try_from(body.clone()).unwrap();
        let decoded =
            SszExecutionPayloadBodyV1::<E>::from_ssz_bytes(&ssz_body.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, ssz_body);

        assert_eq!(ExecutionPayloadBodyV2::try_from(decoded).unwrap(), body);
    }

    #[test]
    fn shanghai_body_v2_round_trips_from_body_v2() {
        let body = ExecutionPayloadBodyV2::<E> {
            transactions: progressive_transactions(),
            withdrawals: Some(ProgressiveVariableList::new(withdrawals().to_vec()).unwrap()),
            block_access_list: None,
        };

        let ssz_body = SszExecutionPayloadBodyV2::try_from(body.clone()).unwrap();
        let decoded =
            SszExecutionPayloadBodyV2::<E>::from_ssz_bytes(&ssz_body.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, ssz_body);

        assert_eq!(ExecutionPayloadBodyV2::try_from(decoded).unwrap(), body);
    }

    /// `VALID` with a latest valid hash and no validation error encodes as the fixed part, then
    /// the hash with no inner offset, with nothing for the empty error list, and decodes back.
    #[test]
    fn valid_payload_status_with_latest_valid_hash_encodes_and_decodes() {
        let latest_valid_hash = Hash256::repeat_byte(0x11);
        let status = PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: Some(ExecutionBlockHash::from_root(latest_valid_hash)),
            validation_error: None,
            inclusion_list_satisfied: None,
        };

        let expected = [
            [0u8].as_slice(),             // status: VALID
            &9u32.to_le_bytes(),          // offset of latest_valid_hash
            &41u32.to_le_bytes(),         // offset of validation_error
            latest_valid_hash.as_slice(), // latest_valid_hash
        ]
        .concat();

        let encoded = SszPayloadStatusV1::try_from(status.clone())
            .unwrap()
            .as_ssz_bytes();
        assert_eq!(encoded, expected);

        let decoded = SszPayloadStatusV1::from_ssz_bytes(&expected).unwrap();
        assert_eq!(PayloadStatusV1::try_from(decoded).unwrap(), status);
    }

    /// `INVALID` with no latest valid hash and a validation error encodes as the fixed part, then
    /// nothing for the empty hash list, then the error list: an inner offset before the error text.
    #[test]
    fn invalid_payload_status_with_validation_error_encodes_and_decodes() {
        let validation_error = "bad state root";
        let status = PayloadStatusV1 {
            status: PayloadStatusV1Status::Invalid,
            latest_valid_hash: None,
            validation_error: Some(validation_error.to_string()),
            inclusion_list_satisfied: None,
        };

        let expected = [
            [1u8].as_slice(),            // status: INVALID
            &9u32.to_le_bytes(),         // offset of latest_valid_hash
            &9u32.to_le_bytes(),         // offset of validation_error
            &4u32.to_le_bytes(),         // inner offset of the error text
            validation_error.as_bytes(), // validation_error
        ]
        .concat();

        let encoded = SszPayloadStatusV1::try_from(status.clone())
            .unwrap()
            .as_ssz_bytes();
        assert_eq!(encoded, expected);

        let decoded = SszPayloadStatusV1::from_ssz_bytes(&expected).unwrap();
        assert_eq!(PayloadStatusV1::try_from(decoded).unwrap(), status);
    }

    #[test]
    fn get_payload_response_for_all_forks() {
        let block_value = Uint256::from(7);

        for fork in ForkName::list_all() {
            let (bytes, expected) = match fork {
                ForkName::Base | ForkName::Altair => {
                    assert!(SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(&[], fork).is_err());
                    continue;
                }
                ForkName::Bellatrix => {
                    let response = SszGetPayloadResponseBellatrix {
                        execution_payload: Default::default(),
                        block_value,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Bellatrix(response),
                    )
                }
                ForkName::Capella => {
                    let response = SszGetPayloadResponseCapella {
                        execution_payload: Default::default(),
                        block_value,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Capella(response),
                    )
                }
                ForkName::Deneb => {
                    let response = SszGetPayloadResponseDeneb {
                        execution_payload: Default::default(),
                        block_value,
                        blobs_bundle: BlobsBundle::default(),
                        should_override_builder: true,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Deneb(response),
                    )
                }
                ForkName::Electra => {
                    let response = SszGetPayloadResponseElectra {
                        execution_payload: Default::default(),
                        block_value,
                        blobs_bundle: BlobsBundle::default(),
                        requests: VariableList::empty(),
                        should_override_builder: true,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Electra(response),
                    )
                }
                ForkName::Fulu => {
                    let response = SszGetPayloadResponseFulu {
                        execution_payload: Default::default(),
                        block_value,
                        blobs_bundle: BlobsBundle::default(),
                        requests: VariableList::empty(),
                        should_override_builder: true,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Fulu(response),
                    )
                }
                ForkName::Gloas => {
                    let response = SszGetPayloadResponseGloas {
                        execution_payload: Default::default(),
                        block_value,
                        blobs_bundle: BlobsBundle::default(),
                        requests: VariableList::empty(),
                        should_override_builder: true,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Gloas(response),
                    )
                }
                ForkName::Heze => {
                    let response = SszGetPayloadResponseHeze {
                        execution_payload: Default::default(),
                        block_value,
                        blobs_bundle: BlobsBundle::default(),
                        requests: VariableList::empty(),
                        should_override_builder: true,
                    };
                    (
                        response.as_ssz_bytes(),
                        SszGetPayloadResponse::Heze(response),
                    )
                }
            };

            assert_eq!(
                SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(&bytes, fork).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn bodies_response_for_all_forks() {
        let v1 = SszBodiesResponseV1::<E> {
            entries: VariableList::new(vec![SszBodyEntryV1 {
                available: true,
                body: SszExecutionPayloadBodyV1 {
                    transactions: transactions(),
                },
            }])
            .unwrap(),
        };
        let v1 = (v1.as_ssz_bytes(), SszBodiesResponse::V1(v1));

        let v2 = SszBodiesResponseV2::<E> {
            entries: VariableList::new(vec![SszBodyEntryV2 {
                available: true,
                body: SszExecutionPayloadBodyV2 {
                    transactions: transactions(),
                    withdrawals: withdrawals(),
                },
            }])
            .unwrap(),
        };
        let v2 = (v2.as_ssz_bytes(), SszBodiesResponse::V2(v2));

        let v3 = SszBodiesResponseV3::<E> {
            entries: VariableList::new(vec![SszBodyEntryV3 {
                available: true,
                body: SszExecutionPayloadBodyV3 {
                    transactions: transactions(),
                    withdrawals: withdrawals(),
                    block_access_list: VariableList::new(vec![0xab; 5]).unwrap(),
                },
            }])
            .unwrap(),
        };
        let v3 = (v3.as_ssz_bytes(), SszBodiesResponse::V3(v3));

        for fork in ForkName::list_all() {
            let (bytes, expected) = match fork {
                ForkName::Base | ForkName::Altair => {
                    assert!(SszBodiesResponse::<E>::from_ssz_bytes_by_fork(&[], fork).is_err());
                    continue;
                }
                ForkName::Bellatrix => &v1,
                ForkName::Capella | ForkName::Deneb | ForkName::Electra | ForkName::Fulu => &v2,
                ForkName::Gloas | ForkName::Heze => &v3,
            };

            assert_eq!(
                SszBodiesResponse::from_ssz_bytes_by_fork(bytes, fork).unwrap(),
                *expected
            );
        }
    }

    fn request_bytes(request_type: RequestType, request: &impl Encode) -> Vec<u8> {
        [vec![request_type.to_u8()], request.as_ssz_bytes()].concat()
    }

    fn ssz_requests(requests: Vec<Vec<u8>>) -> SszExecutionRequests<E> {
        VariableList::new(
            requests
                .into_iter()
                .map(|request| VariableList::new(request).unwrap())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn execution_requests_parse_errors() {
        let deposit = request_bytes(RequestType::Deposit, &deposit_request());
        let withdrawal = request_bytes(RequestType::Withdrawal, &withdrawal_request());

        // Empty element, and a type byte with no request data.
        for request in [vec![], vec![RequestType::Deposit.to_u8()]] {
            assert!(matches!(
                execution_requests_electra_from_ssz::<E>(ssz_requests(vec![request])),
                Err(RequestsError::EmptyRequest(0))
            ));
        }

        // Out of order, and the same type twice.
        for requests in [
            vec![withdrawal, deposit.clone()],
            vec![deposit.clone(), deposit],
        ] {
            assert!(matches!(
                execution_requests_electra_from_ssz::<E>(ssz_requests(requests)),
                Err(RequestsError::InvalidOrdering)
            ));
        }

        // Builder requests before Gloas.
        let builder_deposit = request_bytes(
            RequestType::BuilderDeposit,
            &BuilderDepositRequest {
                pubkey: PublicKeyBytes::empty(),
                withdrawal_credentials: Hash256::repeat_byte(4),
                amount: 34,
                signature: SignatureBytes::empty(),
            },
        );
        let builder_exit = request_bytes(
            RequestType::BuilderExit,
            &BuilderExitRequest {
                source_address: Address::repeat_byte(5),
                pubkey: PublicKeyBytes::empty(),
            },
        );
        for request in [builder_deposit, builder_exit] {
            assert!(matches!(
                execution_requests_electra_from_ssz::<E>(ssz_requests(vec![request])),
                Err(RequestsError::VariantMismatch)
            ));
        }
    }

    #[test]
    fn capabilities_from_json() {
        let json = r#"{
            "supported_forks": ["paris", "shanghai", "cancun", "prague", "osaka", "amsterdam", "bogota"],
            "fork_scoped_endpoints": ["payloads", "forkchoice", "bodies"],
            "independently_versioned": { "blobs": ["v1", "v2", "v3", "v4"] },
            "unscoped_endpoints": ["identity"],
            "limits": {
                "bodies.max_count": 32,
                "blobs.max_versioned_hashes": 128,
                "payload.max_bytes": 1048576
            }
        }"#;

        let capabilities =
            SszCapabilities::from(serde_json::from_str::<JsonCapabilities>(json).unwrap());
        assert_eq!(
            capabilities,
            SszCapabilities {
                supported_forks: HashSet::from([
                    ForkName::Bellatrix,
                    ForkName::Capella,
                    ForkName::Deneb,
                    ForkName::Electra,
                    ForkName::Fulu,
                    ForkName::Gloas,
                    ForkName::Heze,
                ]),
                payloads: true,
                forkchoice: true,
                bodies: true,
                blobs_v1: true,
                blobs_v2: true,
                blobs_v3: true,
                blobs_v4: true,
                unscoped_endpoints: vec!["identity".to_string()],
                limits: SszLimits {
                    bodies_max_count: Some(32),
                    blobs_max_versioned_hashes: Some(128),
                    payload_max_bytes: Some(1048576),
                },
            }
        );
        assert!(capabilities.get_client_version_v1());

        let empty = SszCapabilities::from(serde_json::from_str::<JsonCapabilities>("{}").unwrap());
        assert_eq!(empty, SszCapabilities::default());
    }

    #[test]
    fn blobs_v2_response_rejects_unavailable_entry() {
        let entry = |available| BlobsEntryV2::<E> {
            available,
            contents: BlobAndProofV2 {
                blob: Default::default(),
                proofs: Default::default(),
            },
        };

        let complete = SszBlobsResponseV2 {
            entries: VariableList::new(vec![entry(true), entry(true)]).unwrap(),
        };
        assert_eq!(complete.into_v2().unwrap().len(), 2);

        let partial = SszBlobsResponseV2 {
            entries: VariableList::new(vec![entry(true), entry(false)]).unwrap(),
        };
        assert!(matches!(partial.into_v2(), Err(Error::BadResponse(_))));
    }
}
