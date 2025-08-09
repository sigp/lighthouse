//! HTTP client constants including headers and API versions.

use crate::types::EndpointVersion;

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);
pub const V3: EndpointVersion = EndpointVersion(3);

pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";
pub const EXECUTION_PAYLOAD_BLINDED_HEADER: &str = "Eth-Execution-Payload-Blinded";
pub const EXECUTION_PAYLOAD_VALUE_HEADER: &str = "Eth-Execution-Payload-Value";
pub const CONSENSUS_BLOCK_VALUE_HEADER: &str = "Eth-Consensus-Block-Value";

pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const SSZ_CONTENT_TYPE_HEADER: &str = "application/octet-stream";
pub const JSON_CONTENT_TYPE_HEADER: &str = "application/json";