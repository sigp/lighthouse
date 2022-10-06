use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRequestBody<'a> {
    pub jsonrpc: &'a str,
    pub method: &'a str,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonResponseBody {
    pub jsonrpc: String,
    #[serde(default)]
    pub error: Option<JsonError>,
    #[serde(default)]
    pub result: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentJsonPayloadId(#[serde(with = "eth2_serde_utils::bytes_8_hex")] pub PayloadId);

impl From<PayloadId> for TransparentJsonPayloadId {
    fn from(id: PayloadId) -> Self {
        Self(id)
    }
}

impl From<TransparentJsonPayloadId> for PayloadId {
    fn from(wrapper: TransparentJsonPayloadId) -> Self {
        wrapper.0
    }
}

/// On the request, use a transparent wrapper.
pub type JsonPayloadIdRequest = TransparentJsonPayloadId;

/// On the response, expect without the object wrapper (non-transparent).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPayloadIdResponse {
    #[serde(with = "eth2_serde_utils::bytes_8_hex")]
    pub payload_id: PayloadId,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<TransparentJsonPayloadId>,
}

impl From<JsonForkchoiceUpdatedResponse> for ForkchoiceUpdatedResponse {
    fn from(j: JsonForkchoiceUpdatedResponse) -> Self {
        let JsonForkchoiceUpdatedResponse {
            payload_status: status,
            payload_id,
        } = j;

        Self {
            payload_status: status,
            payload_id: payload_id.map(Into::into),
        }
    }
}
impl From<ForkchoiceUpdatedResponse> for JsonForkchoiceUpdatedResponse {
    fn from(f: ForkchoiceUpdatedResponse) -> Self {
        let ForkchoiceUpdatedResponse {
            payload_status: status,
            payload_id,
        } = f;

        Self {
            payload_status: status,
            payload_id: payload_id.map(Into::into),
        }
    }
}
