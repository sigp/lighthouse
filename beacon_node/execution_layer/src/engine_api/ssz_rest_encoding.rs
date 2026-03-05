//! SSZ encoding/decoding for the Engine API SSZ-REST transport (EIP-8161).
//!
//! This module handles the wire format for SSZ-REST Engine API calls,
//! matching the format used by geth/erigon/nethermind servers.

use crate::engine_api::{
    BlobsBundle, ForkchoiceUpdatedResponse, GetPayloadResponse, GetPayloadResponseDeneb,
    GetPayloadResponseElectra, GetPayloadResponseFulu, GetPayloadResponseGloas, PayloadAttributes,
    PayloadId, PayloadStatusV1, PayloadStatusV1Status,
};
use crate::engines::ForkchoiceState;
use ssz::{Decode, Encode};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::VariableList;
use typenum::{U64, U128};
use types::{
    EthSpec, ExecutionBlockHash, ExecutionPayloadDeneb, ExecutionPayloadElectra,
    ExecutionPayloadFulu, ExecutionPayloadGloas, ExecutionPayloadRef, ExecutionRequests, ForkName,
    Hash256, Uint256, VersionedHash,
};

/// Errors that can occur during SSZ-REST encoding/decoding.
#[derive(Debug)]
pub enum SszRestCodecError {
    /// The response buffer is too short.
    BufferTooShort { expected: usize, actual: usize },
    /// An offset points outside the buffer.
    InvalidOffset { offset: usize, len: usize },
    /// Unknown status byte value.
    UnknownStatus(u8),
    /// Unknown union selector.
    UnknownSelector(u8),
    /// UTF-8 decoding failed.
    Utf8Error(std::string::FromUtf8Error),
    /// Generic decoding error.
    Other(String),
}

impl std::fmt::Display for SszRestCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "SSZ-REST buffer too short: expected at least {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidOffset { offset, len } => {
                write!(
                    f,
                    "SSZ-REST invalid offset: {} exceeds buffer length {}",
                    offset, len
                )
            }
            Self::UnknownStatus(s) => write!(f, "SSZ-REST unknown status byte: {}", s),
            Self::UnknownSelector(s) => write!(f, "SSZ-REST unknown union selector: {}", s),
            Self::Utf8Error(e) => write!(f, "SSZ-REST UTF-8 error: {}", e),
            Self::Other(msg) => write!(f, "SSZ-REST error: {}", msg),
        }
    }
}

impl From<std::string::FromUtf8Error> for SszRestCodecError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, SszRestCodecError> {
    if buf.len() < offset + 4 {
        return Err(SszRestCodecError::BufferTooShort {
            expected: offset + 4,
            actual: buf.len(),
        });
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, SszRestCodecError> {
    if buf.len() < offset + 8 {
        return Err(SszRestCodecError::BufferTooShort {
            expected: offset + 8,
            actual: buf.len(),
        });
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Write a Hash256 (B256) as 32 bytes.
fn write_hash256(buf: &mut Vec<u8>, hash: &Hash256) {
    buf.extend_from_slice(hash.as_slice());
}

/// Write an ExecutionBlockHash as 32 bytes.
fn write_execution_block_hash(buf: &mut Vec<u8>, hash: &ExecutionBlockHash) {
    buf.extend_from_slice(hash.0.as_slice());
}

/// Encode an ExecutionPayloadRef to SSZ bytes by matching on the variant.
fn encode_execution_payload_ref<E: EthSpec>(payload: ExecutionPayloadRef<'_, E>) -> Vec<u8> {
    match payload {
        ExecutionPayloadRef::Bellatrix(p) => p.as_ssz_bytes(),
        ExecutionPayloadRef::Capella(p) => p.as_ssz_bytes(),
        ExecutionPayloadRef::Deneb(p) => p.as_ssz_bytes(),
        ExecutionPayloadRef::Electra(p) => p.as_ssz_bytes(),
        ExecutionPayloadRef::Fulu(p) => p.as_ssz_bytes(),
        ExecutionPayloadRef::Gloas(p) => p.as_ssz_bytes(),
    }
}

// ---------------------------------------------------------------------------
// PayloadStatus decoding
// ---------------------------------------------------------------------------

fn decode_status_byte(b: u8) -> Result<PayloadStatusV1Status, SszRestCodecError> {
    match b {
        0 => Ok(PayloadStatusV1Status::Valid),
        1 => Ok(PayloadStatusV1Status::Invalid),
        2 => Ok(PayloadStatusV1Status::Syncing),
        3 => Ok(PayloadStatusV1Status::Accepted),
        4 => Ok(PayloadStatusV1Status::InvalidBlockHash),
        _ => Err(SszRestCodecError::UnknownStatus(b)),
    }
}

/// Decode a PayloadStatus from SSZ bytes.
///
/// Fixed part (9 bytes):
///   - status: uint8 (1 byte)
///   - latest_valid_hash offset: uint32 LE (4 bytes)
///   - validation_error offset: uint32 LE (4 bytes)
///
/// Variable part:
///   - latest_valid_hash: Union[None, Hash32] (selector byte + optional 32 bytes)
///   - validation_error: List[uint8, 1024]
pub fn decode_payload_status(buf: &[u8]) -> Result<PayloadStatusV1, SszRestCodecError> {
    if buf.len() < 9 {
        return Err(SszRestCodecError::BufferTooShort {
            expected: 9,
            actual: buf.len(),
        });
    }

    let status = decode_status_byte(buf[0])?;
    let lvh_offset = read_u32_le(buf, 1)? as usize;
    let ve_offset = read_u32_le(buf, 5)? as usize;

    if lvh_offset > buf.len() || ve_offset > buf.len() {
        return Err(SszRestCodecError::InvalidOffset {
            offset: std::cmp::max(lvh_offset, ve_offset),
            len: buf.len(),
        });
    }

    let lvh_data = &buf[lvh_offset..ve_offset];
    let latest_valid_hash = if lvh_data.is_empty() {
        None
    } else {
        let selector = lvh_data[0];
        match selector {
            0 => None,
            1 => {
                if lvh_data.len() < 33 {
                    return Err(SszRestCodecError::BufferTooShort {
                        expected: 33,
                        actual: lvh_data.len(),
                    });
                }
                let hash = Hash256::from_slice(&lvh_data[1..33]);
                Some(ExecutionBlockHash::from_root(hash))
            }
            _ => return Err(SszRestCodecError::UnknownSelector(selector)),
        }
    };

    let ve_data = &buf[ve_offset..];
    let validation_error = if ve_data.is_empty() {
        None
    } else {
        Some(String::from_utf8(ve_data.to_vec())?)
    };

    Ok(PayloadStatusV1 {
        status,
        latest_valid_hash,
        validation_error,
    })
}

// ---------------------------------------------------------------------------
// ForkchoiceUpdated request encoding
// ---------------------------------------------------------------------------

/// Encode a ForkchoiceUpdated request.
///
/// Fixed part (100 bytes):
///   - forkchoice_state: 96 bytes (3 x Hash32)
///   - payload_attributes offset: uint32 LE (4 bytes)
///
/// Variable part:
///   - payload_attributes: Union[None, PayloadAttributes]
pub fn encode_forkchoice_updated_request(
    fcs: &ForkchoiceState,
    payload_attributes: &Option<PayloadAttributes>,
) -> Vec<u8> {
    let fixed_size: u32 = 100;
    let mut buf = Vec::with_capacity(256);

    // ForkchoiceState (96 bytes)
    write_execution_block_hash(&mut buf, &fcs.head_block_hash);
    write_execution_block_hash(&mut buf, &fcs.safe_block_hash);
    write_execution_block_hash(&mut buf, &fcs.finalized_block_hash);

    // Offset to payload_attributes
    write_u32_le(&mut buf, fixed_size);

    // Variable: payload_attributes as Union
    match payload_attributes {
        None => {
            buf.push(0); // selector 0 = None
        }
        Some(pa) => {
            buf.push(1); // selector 1 = present
            encode_payload_attributes_into(&mut buf, pa);
        }
    }

    buf
}

/// Encode PayloadAttributes into a buffer.
///
/// Fixed part:
///   - timestamp: uint64 LE (8)
///   - prev_randao: 32 bytes
///   - suggested_fee_recipient: 20 bytes
///   - withdrawals offset: uint32 LE (4)
///   - parent_beacon_block_root: 32 bytes
///
/// Variable:
///   - withdrawals: each 44 bytes (index:8 + validator_index:8 + address:20 + amount:8)
fn encode_payload_attributes_into(buf: &mut Vec<u8>, pa: &PayloadAttributes) {
    let timestamp = pa.timestamp();
    let prev_randao = pa.prev_randao();
    let suggested_fee_recipient = pa.suggested_fee_recipient();

    // Fixed part size: 8 + 32 + 20 + 4 + 32 = 96
    let pa_fixed_size: u32 = 96;

    write_u64_le(buf, timestamp);
    write_hash256(buf, &prev_randao);
    buf.extend_from_slice(suggested_fee_recipient.as_slice());

    match pa {
        PayloadAttributes::V3(v3) => {
            write_u32_le(buf, pa_fixed_size);
            write_hash256(buf, &v3.parent_beacon_block_root);

            for w in &v3.withdrawals {
                write_u64_le(buf, w.index);
                write_u64_le(buf, w.validator_index);
                buf.extend_from_slice(w.address.as_slice());
                write_u64_le(buf, w.amount);
            }
        }
        PayloadAttributes::V2(v2) => {
            write_u32_le(buf, pa_fixed_size);
            buf.extend_from_slice(&[0u8; 32]);

            for w in &v2.withdrawals {
                write_u64_le(buf, w.index);
                write_u64_le(buf, w.validator_index);
                buf.extend_from_slice(w.address.as_slice());
                write_u64_le(buf, w.amount);
            }
        }
        PayloadAttributes::V1(_) => {
            write_u32_le(buf, pa_fixed_size);
            buf.extend_from_slice(&[0u8; 32]);
        }
    }
}

// ---------------------------------------------------------------------------
// ForkchoiceUpdated response decoding
// ---------------------------------------------------------------------------

/// Decode a ForkchoiceUpdated response.
///
/// Fixed part (8 bytes):
///   - payload_status offset: uint32 LE (4)
///   - payload_id offset: uint32 LE (4)
///
/// Variable:
///   - payload_status (same layout as PayloadStatus)
///   - payload_id: Union[None, uint64] (selector byte + 8 bytes)
pub fn decode_forkchoice_updated_response(
    buf: &[u8],
) -> Result<ForkchoiceUpdatedResponse, SszRestCodecError> {
    if buf.len() < 8 {
        return Err(SszRestCodecError::BufferTooShort {
            expected: 8,
            actual: buf.len(),
        });
    }

    let ps_offset = read_u32_le(buf, 0)? as usize;
    let pid_offset = read_u32_le(buf, 4)? as usize;

    if ps_offset > buf.len() || pid_offset > buf.len() {
        return Err(SszRestCodecError::InvalidOffset {
            offset: std::cmp::max(ps_offset, pid_offset),
            len: buf.len(),
        });
    }

    let ps_data = &buf[ps_offset..pid_offset];
    let payload_status = decode_payload_status(ps_data)?;

    let pid_data = &buf[pid_offset..];
    let payload_id = if pid_data.is_empty() {
        None
    } else {
        let selector = pid_data[0];
        match selector {
            0 => None,
            1 => {
                if pid_data.len() < 9 {
                    return Err(SszRestCodecError::BufferTooShort {
                        expected: 9,
                        actual: pid_data.len(),
                    });
                }
                let id = read_u64_le(pid_data, 1)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&id.to_le_bytes());
                Some(arr)
            }
            _ => return Err(SszRestCodecError::UnknownSelector(selector)),
        }
    };

    Ok(ForkchoiceUpdatedResponse {
        payload_status,
        payload_id,
    })
}

// ---------------------------------------------------------------------------
// NewPayload V3 request encoding
// ---------------------------------------------------------------------------

/// Encode a NewPayloadV3 request.
///
/// Fixed part:
///   - execution_payload offset: uint32 LE (4)
///   - versioned_hashes offset: uint32 LE (4)
///   - parent_beacon_block_root: 32 bytes
///
/// Variable:
///   - execution_payload SSZ bytes
///   - versioned_hashes: concatenated 32-byte hashes
pub fn encode_new_payload_v3<E: EthSpec>(
    execution_payload: ExecutionPayloadRef<'_, E>,
    versioned_hashes: &[VersionedHash],
    parent_beacon_block_root: Hash256,
) -> Vec<u8> {
    let payload_ssz = encode_execution_payload_ref(execution_payload);

    // Fixed part: 4 + 4 + 32 = 40 bytes
    let fixed_size: u32 = 40;
    let payload_offset = fixed_size;
    let hashes_offset = payload_offset + payload_ssz.len() as u32;

    let mut buf = Vec::with_capacity(40 + payload_ssz.len() + versioned_hashes.len() * 32);

    write_u32_le(&mut buf, payload_offset);
    write_u32_le(&mut buf, hashes_offset);
    write_hash256(&mut buf, &parent_beacon_block_root);

    buf.extend_from_slice(&payload_ssz);

    for vh in versioned_hashes {
        buf.extend_from_slice(vh.as_slice());
    }

    buf
}

// ---------------------------------------------------------------------------
// NewPayload V4 request encoding
// ---------------------------------------------------------------------------

/// Encode a NewPayloadV4 request (V3 + execution_requests).
///
/// Fixed part:
///   - execution_payload offset: uint32 LE (4)
///   - versioned_hashes offset: uint32 LE (4)
///   - parent_beacon_block_root: 32 bytes
///   - execution_requests offset: uint32 LE (4)
///
/// Variable:
///   - execution_payload SSZ bytes
///   - versioned_hashes: concatenated 32-byte hashes
///   - execution_requests SSZ bytes
pub fn encode_new_payload_v4<E: EthSpec>(
    execution_payload: ExecutionPayloadRef<'_, E>,
    versioned_hashes: &[VersionedHash],
    parent_beacon_block_root: Hash256,
    execution_requests: &types::ExecutionRequests<E>,
) -> Vec<u8> {
    let payload_ssz = encode_execution_payload_ref(execution_payload);
    let requests_list = execution_requests.get_execution_requests_list();

    let mut requests_ssz = Vec::new();
    for req_bytes in &requests_list {
        requests_ssz.extend_from_slice(req_bytes);
    }

    // Fixed part: 4 + 4 + 32 + 4 = 44 bytes
    let fixed_size: u32 = 44;
    let payload_offset = fixed_size;
    let hashes_offset = payload_offset + payload_ssz.len() as u32;
    let requests_offset = hashes_offset + (versioned_hashes.len() as u32) * 32;

    let mut buf = Vec::with_capacity(
        44 + payload_ssz.len() + versioned_hashes.len() * 32 + requests_ssz.len(),
    );

    write_u32_le(&mut buf, payload_offset);
    write_u32_le(&mut buf, hashes_offset);
    write_hash256(&mut buf, &parent_beacon_block_root);
    write_u32_le(&mut buf, requests_offset);

    buf.extend_from_slice(&payload_ssz);

    for vh in versioned_hashes {
        buf.extend_from_slice(vh.as_slice());
    }

    buf.extend_from_slice(&requests_ssz);

    buf
}

// ---------------------------------------------------------------------------
// GetPayload request encoding (8 bytes)
// ---------------------------------------------------------------------------

/// Encode a GetPayload request: 8 bytes (payload ID as uint64 LE).
pub fn encode_get_payload_request(payload_id: &PayloadId) -> Vec<u8> {
    payload_id.to_vec()
}

// ---------------------------------------------------------------------------
// GetBlobs request encoding
// ---------------------------------------------------------------------------

/// Encode a GetBlobs request.
///
/// Container:
///   - versioned_hashes offset: uint32 LE (4) -> concatenated 32-byte hashes
pub fn encode_get_blobs_request(versioned_hashes: &[Hash256]) -> Vec<u8> {
    let fixed_size: u32 = 4;
    let mut buf = Vec::with_capacity(4 + versioned_hashes.len() * 32);
    write_u32_le(&mut buf, fixed_size);
    for vh in versioned_hashes {
        buf.extend_from_slice(vh.as_slice());
    }
    buf
}

// ---------------------------------------------------------------------------
// ExchangeCapabilities encoding/decoding
// ---------------------------------------------------------------------------

/// SSZ type: Container { capabilities: List[List[uint8, 64], 128] }
type Capability = VariableList<u8, U64>;

#[derive(Debug, Clone, SszEncode, SszDecode)]
struct ExchangeCapabilitiesRequest {
    capabilities: VariableList<Capability, U128>,
}

/// Encode capabilities as an SSZ ExchangeCapabilitiesRequest container.
pub fn encode_exchange_capabilities(capabilities: &[&str]) -> Vec<u8> {
    let caps: Vec<Capability> = capabilities
        .iter()
        .map(|s| VariableList::new(s.as_bytes().to_vec()).expect("capability fits in 64 bytes"))
        .collect();
    let request = ExchangeCapabilitiesRequest {
        capabilities: VariableList::new(caps).expect("capabilities list fits in 128 items"),
    };
    request.as_ssz_bytes()
}

/// Decode capabilities from an SSZ ExchangeCapabilitiesRequest container.
pub fn decode_exchange_capabilities(buf: &[u8]) -> Result<Vec<String>, SszRestCodecError> {
    let request = ExchangeCapabilitiesRequest::from_ssz_bytes(buf)
        .map_err(|e| SszRestCodecError::Other(format!("SSZ decode error: {:?}", e)))?;
    let mut result = Vec::with_capacity(request.capabilities.len());
    for cap in request.capabilities.iter() {
        let s = String::from_utf8(cap.to_vec())?;
        result.push(s);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// GetPayload response decoding (stub - complex, fork-dependent)
// ---------------------------------------------------------------------------

/// Decode Uint256 from 32 bytes LE.
fn decode_uint256_le(buf: &[u8]) -> Result<Uint256, SszRestCodecError> {
    if buf.len() < 32 {
        return Err(SszRestCodecError::BufferTooShort {
            expected: 32,
            actual: buf.len(),
        });
    }
    Ok(Uint256::from_le_slice(&buf[..32]))
}

/// Information extracted from a GetPayload response fixed part.
pub struct GetPayloadFixedPart {
    pub execution_payload_offset: usize,
    pub block_value: Uint256,
    pub blobs_bundle_offset: usize,
    pub should_override_builder: bool,
    pub execution_requests_offset: Option<usize>,
}

/// Parse the fixed part of a GetPayload response (V3+ format).
///
/// Fixed part:
///   - execution_payload offset: uint32 LE (4)
///   - block_value: uint256 LE (32)
///   - blobs_bundle offset: uint32 LE (4)
///   - should_override_builder: bool (1)
///   - execution_requests offset: uint32 LE (4) [V4+ only]
pub fn decode_get_payload_fixed(
    buf: &[u8],
    has_execution_requests: bool,
) -> Result<GetPayloadFixedPart, SszRestCodecError> {
    let min_size = if has_execution_requests { 45 } else { 41 };
    if buf.len() < min_size {
        return Err(SszRestCodecError::BufferTooShort {
            expected: min_size,
            actual: buf.len(),
        });
    }

    let ep_offset = read_u32_le(buf, 0)? as usize;
    let block_value = decode_uint256_le(&buf[4..36])?;
    let bb_offset = read_u32_le(buf, 36)? as usize;
    let should_override_builder = buf[40] != 0;

    let er_offset = if has_execution_requests {
        Some(read_u32_le(buf, 41)? as usize)
    } else {
        None
    };

    Ok(GetPayloadFixedPart {
        execution_payload_offset: ep_offset,
        block_value,
        blobs_bundle_offset: bb_offset,
        should_override_builder,
        execution_requests_offset: er_offset,
    })
}

/// Decode a full GetPayload SSZ-REST response into a `GetPayloadResponse`.
///
/// The response format depends on the fork:
/// - V3 (Deneb): fixed(41) = ep_offset(4) + block_value(32) + bb_offset(4) + override(1)
/// - V4+ (Electra/Fulu/Gloas): fixed(45) = above + er_offset(4)
pub fn decode_get_payload_response<E: EthSpec>(
    buf: &[u8],
    fork_name: ForkName,
) -> Result<GetPayloadResponse<E>, SszRestCodecError> {
    let has_requests = matches!(
        fork_name,
        ForkName::Electra | ForkName::Fulu | ForkName::Gloas
    );
    let fixed = decode_get_payload_fixed(buf, has_requests)?;

    let ep_end = fixed.blobs_bundle_offset;
    let ep_bytes = buf
        .get(fixed.execution_payload_offset..ep_end)
        .ok_or(SszRestCodecError::InvalidOffset {
            offset: ep_end,
            len: buf.len(),
        })?;

    let bb_end = fixed
        .execution_requests_offset
        .unwrap_or(buf.len());
    let bb_bytes = buf
        .get(fixed.blobs_bundle_offset..bb_end)
        .ok_or(SszRestCodecError::InvalidOffset {
            offset: bb_end,
            len: buf.len(),
        })?;

    let blobs_bundle = BlobsBundle::<E>::from_ssz_bytes(bb_bytes)
        .map_err(|e| SszRestCodecError::Other(format!("BlobsBundle SSZ decode: {:?}", e)))?;

    match fork_name {
        ForkName::Deneb => {
            let ep = ExecutionPayloadDeneb::<E>::from_ssz_bytes(ep_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionPayload SSZ decode: {:?}", e))
                })?;
            Ok(GetPayloadResponse::Deneb(GetPayloadResponseDeneb {
                execution_payload: ep,
                block_value: fixed.block_value,
                blobs_bundle,
                should_override_builder: fixed.should_override_builder,
            }))
        }
        ForkName::Electra => {
            let ep = ExecutionPayloadElectra::<E>::from_ssz_bytes(ep_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionPayload SSZ decode: {:?}", e))
                })?;
            let er_bytes = &buf[bb_end..];
            let requests = ExecutionRequests::<E>::from_ssz_bytes(er_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionRequests SSZ decode: {:?}", e))
                })?;
            Ok(GetPayloadResponse::Electra(GetPayloadResponseElectra {
                execution_payload: ep,
                block_value: fixed.block_value,
                blobs_bundle,
                should_override_builder: fixed.should_override_builder,
                requests,
            }))
        }
        ForkName::Fulu => {
            let ep = ExecutionPayloadFulu::<E>::from_ssz_bytes(ep_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionPayload SSZ decode: {:?}", e))
                })?;
            let er_bytes = &buf[bb_end..];
            let requests = ExecutionRequests::<E>::from_ssz_bytes(er_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionRequests SSZ decode: {:?}", e))
                })?;
            Ok(GetPayloadResponse::Fulu(GetPayloadResponseFulu {
                execution_payload: ep,
                block_value: fixed.block_value,
                blobs_bundle,
                should_override_builder: fixed.should_override_builder,
                requests,
            }))
        }
        ForkName::Gloas => {
            let ep = ExecutionPayloadGloas::<E>::from_ssz_bytes(ep_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionPayload SSZ decode: {:?}", e))
                })?;
            let er_bytes = &buf[bb_end..];
            let requests = ExecutionRequests::<E>::from_ssz_bytes(er_bytes)
                .map_err(|e| {
                    SszRestCodecError::Other(format!("ExecutionRequests SSZ decode: {:?}", e))
                })?;
            Ok(GetPayloadResponse::Gloas(GetPayloadResponseGloas {
                execution_payload: ep,
                block_value: fixed.block_value,
                blobs_bundle,
                should_override_builder: fixed.should_override_builder,
                requests,
            }))
        }
        _ => Err(SszRestCodecError::Other(format!(
            "SSZ-REST get_payload not supported for fork {}",
            fork_name
        ))),
    }
}
