use bytes::Bytes;
use serde_json::json;
use ssz::{Decode, DecodeError, Encode};
use ssz_types::VariableList;
use types::{EthSpec, ExecutionBlockHash, ExecutionPayload, ForkName, Hash256, Uint256};
use warp::http::Response;

use crate::engine_api::rest::header_to_fork;
use crate::engine_api::{ExecutionPayloadBodyV1, ForkchoiceUpdatedResponse, PayloadAttributes};
use crate::engines::ForkchoiceState;
use crate::json_structures::{BlobAndProof, BlobAndProofV2};
use crate::ssz_structures::*;

use super::handle_rpc::UNKNOWN_PAYLOAD_ERROR_CODE;
use super::mock_engine_core::CorePayload;
use super::{Context, DEFAULT_CLIENT_VERSION, DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI, STUB_CAPABILITIES_JSON};

pub(crate) fn handle_rest<E: EthSpec>(
    method: &str,
    path: &str,
    query: Option<&str>,
    eth_execution_version: Option<&str>,
    body: &Bytes,
    ctx: &Context<E>,
) -> Response<Bytes> {
    match (method, path) {
        ("GET", "/engine/v1/capabilities") => {
            let mut capabilities: serde_json::Value =
                serde_json::from_str(STUB_CAPABILITIES_JSON).unwrap();
            if !ctx.engine_capabilities.read().get_client_version_v1()
                && let Some(endpoints) = capabilities["unscoped_endpoints"].as_array_mut()
            {
                endpoints.retain(|e| e.as_str() != Some("identity"));
            }
            json_response(Bytes::from(serde_json::to_vec(&capabilities).unwrap()))
        }
        ("GET", "/engine/v1/identity") => json_response(Bytes::from(
            serde_json::to_vec(&[DEFAULT_CLIENT_VERSION.clone()]).unwrap(),
        )),
        ("POST", "/engine/v1/payloads") => {
            let Some(fork) = eth_execution_version.and_then(header_to_fork) else {
                return problem_response(
                    RestProblemKind::UnsupportedFork,
                    eth_execution_version.map(|header| header.to_string()),
                );
            };

            let payload = match decode_new_payload::<E>(body, fork) {
                Ok(payload) => payload,
                Err(_) => return problem_response(RestProblemKind::SszDecodeError, None),
            };

            let status = match ctx.core_new_payload(payload) {
                Ok(status) => status,
                Err(err) => return core_error_response(err),
            };

            match SszPayloadStatusV1::<E>::try_from(status) {
                Ok(ssz) => ssz_response(Bytes::from(ssz.as_ssz_bytes())),
                Err(e) => problem_response(RestProblemKind::Internal, Some(format!("{e:?}"))),
            }
        }
        ("POST", "/engine/v1/forkchoice") => {
            let Some(fork) = eth_execution_version.and_then(header_to_fork) else {
                return problem_response(
                    RestProblemKind::UnsupportedFork,
                    eth_execution_version.map(|header| header.to_string()),
                );
            };

            let (state, attributes) = match decode_forkchoice_updated::<E>(body, fork) {
                Ok(decoded) => decoded,
                Err(_) => return problem_response(RestProblemKind::SszDecodeError, None),
            };

            let response = match ctx.core_forkchoice_updated(state, attributes) {
                Ok(response) => response,
                Err(err) => return core_error_response(err),
            };

            match SszForkchoiceUpdatedResponse::<E>::try_from(ForkchoiceUpdatedResponse::from(
                response,
            )) {
                Ok(ssz) => ssz_response(Bytes::from(ssz.as_ssz_bytes())),
                Err(e) => problem_response(RestProblemKind::Internal, Some(format!("{e:?}"))),
            }
        }
        ("GET", path) if path.starts_with("/engine/v1/payloads/") => {
            if eth_execution_version.and_then(header_to_fork).is_none() {
                return problem_response(
                    RestProblemKind::UnsupportedFork,
                    eth_execution_version.map(|header| header.to_string()),
                );
            }

            let Some(payload_id) = path
                .strip_prefix("/engine/v1/payloads/")
                .and_then(|segment| segment.strip_prefix("0x"))
                .and_then(|hex| hex::decode(hex).ok())
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            else {
                return problem_response(
                    RestProblemKind::InvalidRequest,
                    Some(format!("malformed payload id: {path}")),
                );
            };

            let core = match ctx.core_get_payload(payload_id) {
                Ok(core) => core,
                Err(err) => return core_error_response(err),
            };

            match encode_get_payload(core) {
                Ok(bytes) => ssz_response_no_store(Bytes::from(bytes)),
                Err(e) => problem_response(RestProblemKind::Internal, Some(e)),
            }
        }
        ("POST", "/engine/v1/blobs/v2") => handle_get_blobs(ctx, body, true),
        ("POST", "/engine/v1/blobs/v3") => handle_get_blobs(ctx, body, false),
        ("POST", "/engine/v1/bodies/hash") => {
            let Some(fork) = eth_execution_version.and_then(header_to_fork) else {
                return problem_response(
                    RestProblemKind::UnsupportedFork,
                    eth_execution_version.map(|header| header.to_string()),
                );
            };

            let block_hashes = match decode_bodies_by_hash_request(body) {
                Ok(hashes) => hashes,
                Err(_) => return problem_response(RestProblemKind::SszDecodeError, None),
            };

            let generator = ctx.execution_block_generator.read();
            let payloads = block_hashes
                .into_iter()
                .map(|hash| generator.execution_payload_by_hash(ExecutionBlockHash::from_root(hash)))
                .collect();
            drop(generator);

            match encode_bodies_response(payloads, fork) {
                Ok(bytes) => ssz_response(Bytes::from(bytes)),
                Err(e) => problem_response(RestProblemKind::Internal, Some(e)),
            }
        }
        ("GET", "/engine/v1/bodies") => {
            let Some(fork) = eth_execution_version.and_then(header_to_fork) else {
                return problem_response(
                    RestProblemKind::UnsupportedFork,
                    eth_execution_version.map(|header| header.to_string()),
                );
            };

            let Some((from, count)) = parse_from_count(query) else {
                return problem_response(
                    RestProblemKind::InvalidRequest,
                    Some("malformed bodies range query".to_string()),
                );
            };

            let generator = ctx.execution_block_generator.read();
            let payloads = (from..from.saturating_add(count))
                .map(|number| generator.execution_payload_by_number(number))
                .collect();
            drop(generator);

            match encode_bodies_response(payloads, fork) {
                Ok(bytes) => ssz_response(Bytes::from(bytes)),
                Err(e) => problem_response(RestProblemKind::Internal, Some(e)),
            }
        }
        _ => problem_response(RestProblemKind::MethodNotFound, None),
    }
}

fn json_response(body: Bytes) -> Response<Bytes> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap()
}

fn ssz_response(body: Bytes) -> Response<Bytes> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .unwrap()
}

fn ssz_response_no_store(body: Bytes) -> Response<Bytes> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/octet-stream")
        .header("Cache-Control", "no-store")
        .body(body)
        .unwrap()
}

fn decode_new_payload<E: EthSpec>(
    body: &[u8],
    fork: ForkName,
) -> Result<ExecutionPayload<E>, DecodeError> {
    Ok(match fork {
        ForkName::Bellatrix => ExecutionPayload::Bellatrix(
            SszExecutionPayloadEnvelopeBellatrix::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Capella => ExecutionPayload::Capella(
            SszExecutionPayloadEnvelopeCapella::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Deneb => ExecutionPayload::Deneb(
            SszExecutionPayloadEnvelopeDeneb::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Electra => ExecutionPayload::Electra(
            SszExecutionPayloadEnvelopeElectra::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Fulu => ExecutionPayload::Fulu(
            SszExecutionPayloadEnvelopeFulu::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Gloas => ExecutionPayload::Gloas(
            SszExecutionPayloadEnvelopeGloas::from_ssz_bytes(body)?.execution_payload,
        ),
        ForkName::Base | ForkName::Altair => {
            return Err(DecodeError::BytesInvalid(format!(
                "unsupported fork for new_payload envelope: {fork}"
            )));
        }
    })
}

fn decode_forkchoice_updated<E: EthSpec>(
    body: &[u8],
    fork: ForkName,
) -> Result<(ForkchoiceState, Option<PayloadAttributes>), DecodeError> {
    Ok(match fork {
        ForkName::Bellatrix => {
            let update = SszForkchoiceUpdateBellatrix::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V1))
        }
        ForkName::Capella => {
            let update = SszForkchoiceUpdateCapella::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V2))
        }
        ForkName::Deneb => {
            let update = SszForkchoiceUpdateDeneb::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V3))
        }
        ForkName::Electra => {
            let update = SszForkchoiceUpdateElectra::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V3))
        }
        ForkName::Fulu => {
            let update = SszForkchoiceUpdateFulu::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V3))
        }
        ForkName::Gloas => {
            let update = SszForkchoiceUpdateAmsterdam::<E>::from_ssz_bytes(body)?;
            let attributes = update.payload_attributes.first().cloned();
            (update.forkchoice_state, attributes.map(PayloadAttributes::V4))
        }
        ForkName::Base | ForkName::Altair => {
            return Err(DecodeError::BytesInvalid(format!(
                "unsupported fork for forkchoice update: {fork}"
            )));
        }
    })
}

fn encode_get_payload<E: EthSpec>(core: CorePayload<E>) -> Result<Vec<u8>, String> {
    let CorePayload {
        payload,
        blobs,
        requests,
        fork: _,
    } = core;
    let block_value = Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI);

    let ssz_requests = match requests {
        Some(requests) => execution_requests_to_ssz(requests).map_err(|e| format!("{e:?}"))?,
        None => Default::default(),
    };

    let bytes = match payload {
        ExecutionPayload::Bellatrix(execution_payload) => SszGetPayloadResponseBellatrix {
            execution_payload,
            block_value,
        }
        .as_ssz_bytes(),
        ExecutionPayload::Capella(execution_payload) => SszGetPayloadResponseCapella {
            execution_payload,
            block_value,
        }
        .as_ssz_bytes(),
        ExecutionPayload::Deneb(execution_payload) => SszGetPayloadResponseDeneb {
            execution_payload,
            block_value,
            blobs_bundle: blobs.unwrap_or_default(),
            should_override_builder: false,
        }
        .as_ssz_bytes(),
        ExecutionPayload::Electra(execution_payload) => SszGetPayloadResponseElectra {
            execution_payload,
            block_value,
            blobs_bundle: blobs.unwrap_or_default(),
            requests: ssz_requests,
            should_override_builder: false,
        }
        .as_ssz_bytes(),
        ExecutionPayload::Fulu(execution_payload) => SszGetPayloadResponseFulu {
            execution_payload,
            block_value,
            blobs_bundle: blobs.unwrap_or_default(),
            requests: ssz_requests,
            should_override_builder: false,
        }
        .as_ssz_bytes(),
        ExecutionPayload::Gloas(execution_payload) => SszGetPayloadResponseGloas {
            execution_payload,
            block_value,
            blobs_bundle: blobs.unwrap_or_default(),
            requests: ssz_requests,
            should_override_builder: false,
        }
        .as_ssz_bytes(),
    };

    Ok(bytes)
}

fn decode_blobs_request<E: EthSpec>(body: &[u8]) -> Result<Vec<Hash256>, DecodeError> {
    Ok(SszBlobsRequestV1::<E>::from_ssz_bytes(body)?
        .versioned_hashes
        .to_vec())
}

fn no_content_response() -> Response<Bytes> {
    Response::builder().status(204).body(Bytes::new()).unwrap()
}

/// `all_or_nothing = true` for `/blobs/v2` (any miss ⇒ `204`), `false` for `/blobs/v3` (partial).
fn handle_get_blobs<E: EthSpec>(
    ctx: &Context<E>,
    body: &[u8],
    all_or_nothing: bool,
) -> Response<Bytes> {
    let versioned_hashes = match decode_blobs_request::<E>(body) {
        Ok(hashes) => hashes,
        Err(_) => return problem_response(RestProblemKind::SszDecodeError, None),
    };

    let generator = ctx.execution_block_generator.read();
    let mut entries = Vec::with_capacity(versioned_hashes.len());
    let mut all_present = true;
    for hash in &versioned_hashes {
        match generator.get_blob_and_proof(hash) {
            Some(BlobAndProof::V2(contents)) => entries.push(BlobsEntry {
                available: true,
                contents,
            }),
            _ => {
                all_present = false;
                entries.push(BlobsEntry {
                    available: false,
                    contents: BlobAndProofV2 {
                        blob: Default::default(),
                        proofs: Default::default(),
                    },
                });
            }
        }
    }

    if all_or_nothing && !all_present {
        return no_content_response();
    }

    let entries = match VariableList::new(entries) {
        Ok(entries) => entries,
        Err(e) => return problem_response(RestProblemKind::Internal, Some(format!("{e:?}"))),
    };
    ssz_response(Bytes::from(SszBlobsResponse { entries }.as_ssz_bytes()))
}

fn encode_bodies_response<E: EthSpec>(
    payloads: Vec<Option<ExecutionPayload<E>>>,
    fork: ForkName,
) -> Result<Vec<u8>, String> {
    let bodies: Vec<(bool, ExecutionPayloadBodyV1<E>)> = payloads
        .into_iter()
        .map(|maybe_payload| match maybe_payload {
            Some(payload) => (
                true,
                ExecutionPayloadBodyV1 {
                    transactions: payload.transactions().clone(),
                    withdrawals: payload.withdrawals().ok().cloned(),
                },
            ),
            None => (
                false,
                ExecutionPayloadBodyV1 {
                    transactions: Default::default(),
                    withdrawals: None,
                },
            ),
        })
        .collect();

    let bytes = match fork {
        ForkName::Bellatrix => {
            let entries = bodies
                .into_iter()
                .map(|(available, body)| SszBodyEntryV1 {
                    available,
                    body: SszExecutionPayloadBodyV1::from(body),
                })
                .collect::<Vec<_>>();
            SszBodiesResponseV1 {
                entries: VariableList::new(entries).map_err(|e| format!("{e:?}"))?,
            }
            .as_ssz_bytes()
        }
        ForkName::Capella | ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
            let entries = bodies
                .into_iter()
                .map(|(available, body)| {
                    Ok(SszBodyEntryV2 {
                        available,
                        body: SszExecutionPayloadBodyV2::try_from(body)
                            .map_err(|e| format!("{e:?}"))?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            SszBodiesResponseV2 {
                entries: VariableList::new(entries).map_err(|e| format!("{e:?}"))?,
            }
            .as_ssz_bytes()
        }
        ForkName::Gloas => {
            return Err("amsterdam execution payload bodies are not yet supported".to_string());
        }
        ForkName::Base | ForkName::Altair => {
            return Err(format!("unsupported fork for execution payload bodies: {fork}"));
        }
    };

    Ok(bytes)
}

fn decode_bodies_by_hash_request(body: &[u8]) -> Result<Vec<Hash256>, DecodeError> {
    Ok(SszBodiesByHashRequest::from_ssz_bytes(body)?
        .block_hashes
        .to_vec())
}

fn parse_from_count(query: Option<&str>) -> Option<(u64, u64)> {
    let query = query?;
    let mut from = None;
    let mut count = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        match key {
            "from" => from = value.parse().ok(),
            "count" => count = value.parse().ok(),
            _ => {}
        }
    }
    Some((from?, count?))
}

pub enum RestProblemKind {
    UnsupportedFork,
    SszDecodeError,
    InvalidRequest,
    MethodNotFound,
    UnknownPayload,
    Internal,
}

impl RestProblemKind {
    fn status(&self) -> u16 {
        match self {
            RestProblemKind::UnsupportedFork => 400,
            RestProblemKind::SszDecodeError => 400,
            RestProblemKind::InvalidRequest => 400,
            RestProblemKind::MethodNotFound => 404,
            RestProblemKind::UnknownPayload => 404,
            RestProblemKind::Internal => 500,
        }
    }

    fn slug(&self) -> &'static str {
        match self {
            RestProblemKind::UnsupportedFork => "unsupported-fork",
            RestProblemKind::SszDecodeError => "ssz-decode-error",
            RestProblemKind::InvalidRequest => "invalid-request",
            RestProblemKind::MethodNotFound => "method-not-found",
            RestProblemKind::UnknownPayload => "unknown-payload",
            RestProblemKind::Internal => "internal",
        }
    }
}

pub fn problem_response(
    problem: RestProblemKind,
    detail: Option<String>,
) -> Response<Bytes> {
    let body = json!({
        "type": format!("/engine-api/errors/{}", problem.slug()),
        "detail": detail,
    });

    Response::builder()
        .status(problem.status())
        .header("Content-Type", "application/problem+json")
        .body(Bytes::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

pub fn core_error_response((message, code): (String, i64)) -> Response<Bytes> {
    let problem = if code == UNKNOWN_PAYLOAD_ERROR_CODE {
        RestProblemKind::UnknownPayload
    } else {
        RestProblemKind::Internal
    };

    problem_response(problem, Some(message))
}
