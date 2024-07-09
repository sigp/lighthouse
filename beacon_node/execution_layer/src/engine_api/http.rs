//! Contains an implementation of `EngineAPI` using the JSON-RPC API via HTTP.

use super::*;
use crate::auth::Auth;
use crate::json_structures::*;
use lazy_static::lazy_static;
use lighthouse_version::{COMMIT_PREFIX, VERSION};
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashSet;
use tokio::sync::Mutex;

use std::time::{Duration, Instant};

pub use deposit_log::{DepositLog, Log};
pub use reqwest::Client;

const STATIC_ID: u32 = 1;
pub const JSONRPC_VERSION: &str = "2.0";

pub const RETURN_FULL_TRANSACTION_OBJECTS: bool = false;

pub const ETH_GET_BLOCK_BY_NUMBER: &str = "eth_getBlockByNumber";
pub const ETH_GET_BLOCK_BY_NUMBER_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_GET_BLOCK_BY_HASH: &str = "eth_getBlockByHash";
pub const ETH_GET_BLOCK_BY_HASH_TIMEOUT: Duration = Duration::from_secs(1);

pub const ETH_SYNCING: &str = "eth_syncing";
pub const ETH_SYNCING_TIMEOUT: Duration = Duration::from_secs(1);

pub const ENGINE_NEW_PAYLOAD_V1: &str = "engine_newPayloadV1";
pub const ENGINE_NEW_PAYLOAD_V2: &str = "engine_newPayloadV2";
pub const ENGINE_NEW_PAYLOAD_V3: &str = "engine_newPayloadV3";
pub const ENGINE_NEW_PAYLOAD_V4: &str = "engine_newPayloadV4";
pub const ENGINE_NEW_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(8);

pub const ENGINE_GET_PAYLOAD_V1: &str = "engine_getPayloadV1";
pub const ENGINE_GET_PAYLOAD_V2: &str = "engine_getPayloadV2";
pub const ENGINE_GET_PAYLOAD_V3: &str = "engine_getPayloadV3";
pub const ENGINE_GET_PAYLOAD_V4: &str = "engine_getPayloadV4";
pub const ENGINE_GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);

pub const ENGINE_FORKCHOICE_UPDATED_V1: &str = "engine_forkchoiceUpdatedV1";
pub const ENGINE_FORKCHOICE_UPDATED_V2: &str = "engine_forkchoiceUpdatedV2";
pub const ENGINE_FORKCHOICE_UPDATED_V3: &str = "engine_forkchoiceUpdatedV3";
pub const ENGINE_FORKCHOICE_UPDATED_TIMEOUT: Duration = Duration::from_secs(8);

pub const ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1: &str = "engine_getPayloadBodiesByHashV1";
pub const ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1: &str = "engine_getPayloadBodiesByRangeV1";
pub const ENGINE_GET_PAYLOAD_BODIES_TIMEOUT: Duration = Duration::from_secs(10);

pub const ENGINE_EXCHANGE_CAPABILITIES: &str = "engine_exchangeCapabilities";
pub const ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);

pub const ENGINE_GET_CLIENT_VERSION_V1: &str = "engine_getClientVersionV1";
pub const ENGINE_GET_CLIENT_VERSION_TIMEOUT: Duration = Duration::from_secs(1);

/// This error is returned during a `chainId` call by Geth.
pub const EIP155_ERROR_STR: &str = "chain not synced beyond EIP-155 replay-protection fork block";
/// This code is returned by all clients when a method is not supported
/// (verified geth, nethermind, erigon, besu)
pub const METHOD_NOT_FOUND_CODE: i64 = -32601;

pub static LIGHTHOUSE_CAPABILITIES: &[&str] = &[
    ENGINE_NEW_PAYLOAD_V1,
    ENGINE_NEW_PAYLOAD_V2,
    ENGINE_NEW_PAYLOAD_V3,
    ENGINE_NEW_PAYLOAD_V4,
    ENGINE_GET_PAYLOAD_V1,
    ENGINE_GET_PAYLOAD_V2,
    ENGINE_GET_PAYLOAD_V3,
    ENGINE_GET_PAYLOAD_V4,
    ENGINE_FORKCHOICE_UPDATED_V1,
    ENGINE_FORKCHOICE_UPDATED_V2,
    ENGINE_FORKCHOICE_UPDATED_V3,
    ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1,
    ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1,
    ENGINE_GET_CLIENT_VERSION_V1,
];

lazy_static! {
    /// We opt to initialize the JsonClientVersionV1 rather than the ClientVersionV1
    /// for two reasons:
    /// 1. This saves the overhead of converting into Json for every engine call
    /// 2. The Json version lacks error checking so we can avoid calling `unwrap()`
    pub static ref LIGHTHOUSE_JSON_CLIENT_VERSION: JsonClientVersionV1 = JsonClientVersionV1 {
        code: ClientCode::Lighthouse.to_string(),
        name: "Lighthouse".to_string(),
        version: VERSION.replace("Lighthouse/", ""),
        commit: COMMIT_PREFIX.to_string(),
    };
}

/// Contains methods to convert arbitrary bytes to an ETH2 deposit contract object.
pub mod deposit_log {
    use ssz::Decode;
    use state_processing::per_block_processing::signature_sets::deposit_pubkey_signature_message;
    use types::{ChainSpec, DepositData, Hash256, PublicKeyBytes, SignatureBytes};

    pub use eth2::lighthouse::DepositLog;

    /// The following constants define the layout of bytes in the deposit contract `DepositEvent`. The
    /// event bytes are formatted according to the  Ethereum ABI.
    const PUBKEY_START: usize = 192;
    const PUBKEY_LEN: usize = 48;
    const CREDS_START: usize = PUBKEY_START + 64 + 32;
    const CREDS_LEN: usize = 32;
    const AMOUNT_START: usize = CREDS_START + 32 + 32;
    const AMOUNT_LEN: usize = 8;
    const SIG_START: usize = AMOUNT_START + 32 + 32;
    const SIG_LEN: usize = 96;
    const INDEX_START: usize = SIG_START + 96 + 32;
    const INDEX_LEN: usize = 8;

    /// A reduced set of fields from an Eth1 contract log.
    #[derive(Debug, PartialEq, Clone)]
    pub struct Log {
        pub block_number: u64,
        pub data: Vec<u8>,
    }

    impl Log {
        /// Attempts to parse a raw `Log` from the deposit contract into a `DepositLog`.
        pub fn to_deposit_log(&self, spec: &ChainSpec) -> Result<DepositLog, String> {
            let bytes = &self.data;

            let pubkey = bytes
                .get(PUBKEY_START..PUBKEY_START + PUBKEY_LEN)
                .ok_or("Insufficient bytes for pubkey")?;
            let withdrawal_credentials = bytes
                .get(CREDS_START..CREDS_START + CREDS_LEN)
                .ok_or("Insufficient bytes for withdrawal credential")?;
            let amount = bytes
                .get(AMOUNT_START..AMOUNT_START + AMOUNT_LEN)
                .ok_or("Insufficient bytes for amount")?;
            let signature = bytes
                .get(SIG_START..SIG_START + SIG_LEN)
                .ok_or("Insufficient bytes for signature")?;
            let index = bytes
                .get(INDEX_START..INDEX_START + INDEX_LEN)
                .ok_or("Insufficient bytes for index")?;

            let deposit_data = DepositData {
                pubkey: PublicKeyBytes::from_ssz_bytes(pubkey)
                    .map_err(|e| format!("Invalid pubkey ssz: {:?}", e))?,
                withdrawal_credentials: Hash256::from_ssz_bytes(withdrawal_credentials)
                    .map_err(|e| format!("Invalid withdrawal_credentials ssz: {:?}", e))?,
                amount: u64::from_ssz_bytes(amount)
                    .map_err(|e| format!("Invalid amount ssz: {:?}", e))?,
                signature: SignatureBytes::from_ssz_bytes(signature)
                    .map_err(|e| format!("Invalid signature ssz: {:?}", e))?,
            };

            let signature_is_valid = deposit_pubkey_signature_message(&deposit_data, spec)
                .map_or(false, |(public_key, signature, msg)| {
                    signature.verify(&public_key, msg)
                });

            Ok(DepositLog {
                deposit_data,
                block_number: self.block_number,
                index: u64::from_ssz_bytes(index)
                    .map_err(|e| format!("Invalid index ssz: {:?}", e))?,
                signature_is_valid,
            })
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;
        use types::{EthSpec, MainnetEthSpec};

        /// The data from a deposit event, using the v0.8.3 version of the deposit contract.
        pub const EXAMPLE_LOG: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 167, 108, 6, 69, 88, 17,
            3, 51, 6, 4, 158, 232, 82, 248, 218, 2, 71, 219, 55, 102, 86, 125, 136, 203, 36, 77,
            64, 213, 43, 52, 175, 154, 239, 50, 142, 52, 201, 77, 54, 239, 0, 229, 22, 46, 139,
            120, 62, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            8, 0, 64, 89, 115, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 96, 140, 74, 175, 158, 209, 20, 206, 30, 63, 215, 238, 113, 60,
            132, 216, 211, 100, 186, 202, 71, 34, 200, 160, 225, 212, 213, 119, 88, 51, 80, 101,
            74, 2, 45, 78, 153, 12, 192, 44, 51, 77, 40, 10, 72, 246, 34, 193, 187, 22, 95, 4, 211,
            245, 224, 13, 162, 21, 163, 54, 225, 22, 124, 3, 56, 14, 81, 122, 189, 149, 250, 251,
            159, 22, 77, 94, 157, 197, 196, 253, 110, 201, 88, 193, 246, 136, 226, 221, 18, 113,
            232, 105, 100, 114, 103, 237, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        #[test]
        fn can_parse_example_log() {
            let log = Log {
                block_number: 42,
                data: EXAMPLE_LOG.to_vec(),
            };
            log.to_deposit_log(&MainnetEthSpec::default_spec())
                .expect("should decode log");
        }
    }
}

/// Contains subset of the HTTP JSON-RPC methods used to query an execution node for
/// state of the deposit contract.
pub mod deposit_methods {
    use super::Log;
    use crate::HttpJsonRpc;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::fmt;
    use std::ops::Range;
    use std::str::FromStr;
    use std::time::Duration;
    use types::Hash256;

    /// `keccak("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`
    pub const DEPOSIT_EVENT_TOPIC: &str =
        "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5";
    /// `keccak("get_deposit_root()")[0..4]`
    pub const DEPOSIT_ROOT_FN_SIGNATURE: &str = "0xc5f2892f";
    /// `keccak("get_deposit_count()")[0..4]`
    pub const DEPOSIT_COUNT_FN_SIGNATURE: &str = "0x621fd130";

    /// Number of bytes in deposit contract deposit root response.
    pub const DEPOSIT_COUNT_RESPONSE_BYTES: usize = 96;
    /// Number of bytes in deposit contract deposit root (value only).
    pub const DEPOSIT_ROOT_BYTES: usize = 32;

    /// Represents an eth1 chain/network id.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum Eth1Id {
        Mainnet,
        Custom(u64),
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct Block {
        pub hash: Hash256,
        pub timestamp: u64,
        pub number: u64,
    }

    /// Used to identify a block when querying the Eth1 node.
    #[derive(Clone, Copy)]
    pub enum BlockQuery {
        Number(u64),
        Hash(Hash256),
        Latest,
    }

    impl From<Eth1Id> for u64 {
        fn from(from: Eth1Id) -> u64 {
            match from {
                Eth1Id::Mainnet => 1,
                Eth1Id::Custom(id) => id,
            }
        }
    }

    impl From<u64> for Eth1Id {
        fn from(id: u64) -> Self {
            let into = |x: Eth1Id| -> u64 { x.into() };
            match id {
                id if id == into(Eth1Id::Mainnet) => Eth1Id::Mainnet,
                id => Eth1Id::Custom(id),
            }
        }
    }

    impl FromStr for Eth1Id {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.parse::<u64>()
                .map(Into::into)
                .map_err(|e| format!("Failed to parse eth1 network id {}", e))
        }
    }

    /// Represents an error received from a remote procecdure call.
    #[derive(Debug, Serialize, Deserialize)]
    pub enum RpcError {
        NoResultField,
        Eip155Error,
        InvalidJson(String),
        Error(String),
    }

    impl fmt::Display for RpcError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                RpcError::NoResultField => write!(f, "No result field in response"),
                RpcError::Eip155Error => write!(f, "Not synced past EIP-155"),
                RpcError::InvalidJson(e) => write!(f, "Malformed JSON received: {}", e),
                RpcError::Error(s) => write!(f, "{}", s),
            }
        }
    }

    impl From<RpcError> for String {
        fn from(e: RpcError) -> String {
            e.to_string()
        }
    }

    /// Parses a `0x`-prefixed, **big-endian** hex string as a u64.
    ///
    /// Note: the JSON-RPC encodes integers as big-endian. The deposit contract uses little-endian.
    /// Therefore, this function is only useful for numbers encoded by the JSON RPC.
    ///
    /// E.g., `0x01 == 1`
    fn hex_to_u64_be(hex: &str) -> Result<u64, String> {
        u64::from_str_radix(strip_prefix(hex)?, 16)
            .map_err(|e| format!("Failed to parse hex as u64: {:?}", e))
    }

    /// Parses a `0x`-prefixed, big-endian hex string as bytes.
    ///
    /// E.g., `0x0102 == vec![1, 2]`
    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
        hex::decode(strip_prefix(hex)?)
            .map_err(|e| format!("Failed to parse hex as bytes: {:?}", e))
    }

    /// Removes the `0x` prefix from some bytes. Returns an error if the prefix is not present.
    fn strip_prefix(hex: &str) -> Result<&str, String> {
        if let Some(stripped) = hex.strip_prefix("0x") {
            Ok(stripped)
        } else {
            Err("Hex string did not start with `0x`".to_string())
        }
    }

    impl HttpJsonRpc {
        /// Get the eth1 chain id of the given endpoint.
        pub async fn get_chain_id(&self, timeout: Duration) -> Result<Eth1Id, String> {
            let chain_id: String = self
                .rpc_request("eth_chainId", json!([]), timeout)
                .await
                .map_err(|e| format!("eth_chainId call failed {:?}", e))?;
            hex_to_u64_be(chain_id.as_str()).map(|id| id.into())
        }

        /// Returns the current block number.
        pub async fn get_block_number(&self, timeout: Duration) -> Result<u64, String> {
            let response: String = self
                .rpc_request("eth_blockNumber", json!([]), timeout)
                .await
                .map_err(|e| format!("eth_blockNumber call failed {:?}", e))?;
            hex_to_u64_be(response.as_str())
                .map_err(|e| format!("Failed to get block number: {}", e))
        }

        /// Gets a block hash by block number.
        pub async fn get_block(
            &self,
            query: BlockQuery,
            timeout: Duration,
        ) -> Result<Block, String> {
            let (method, query_param) = match query {
                BlockQuery::Number(block_number) => {
                    ("eth_getBlockByNumber", format!("0x{:x}", block_number))
                }
                BlockQuery::Hash(block_hash) => ("eth_getBlockByHash", format!("{:?}", block_hash)),
                BlockQuery::Latest => ("eth_getBlockByNumber", "latest".to_string()),
            };
            let params = json!([
                query_param,
                false // do not return full tx objects.
            ]);

            let response: Value = self
                .rpc_request(method, params, timeout)
                .await
                .map_err(|e| format!("{} call failed {:?}", method, e))?;

            let hash: Vec<u8> = hex_to_bytes(
                response
                    .get("hash")
                    .ok_or("No hash for block")?
                    .as_str()
                    .ok_or("Block hash was not string")?,
            )?;
            let hash: Hash256 = if hash.len() == 32 {
                Hash256::from_slice(&hash)
            } else {
                return Err(format!("Block hash was not 32 bytes: {:?}", hash));
            };

            let timestamp = hex_to_u64_be(
                response
                    .get("timestamp")
                    .ok_or("No timestamp for block")?
                    .as_str()
                    .ok_or("Block timestamp was not string")?,
            )?;

            let number = hex_to_u64_be(
                response
                    .get("number")
                    .ok_or("No number for block")?
                    .as_str()
                    .ok_or("Block number was not string")?,
            )?;

            if number <= usize::MAX as u64 {
                Ok(Block {
                    hash,
                    timestamp,
                    number,
                })
            } else {
                Err(format!("Block number {} is larger than a usize", number))
            }
            .map_err(|e| format!("Failed to get block number: {}", e))
        }

        /// Returns the value of the `get_deposit_count()` call at the given `address` for the given
        /// `block_number`.
        ///
        /// Assumes that the `address` has the same ABI as the eth2 deposit contract.
        pub async fn get_deposit_count(
            &self,
            address: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<u64>, String> {
            let result = self
                .call(address, DEPOSIT_COUNT_FN_SIGNATURE, block_number, timeout)
                .await?;
            match result {
                None => Err("Deposit root response was none".to_string()),
                Some(bytes) => {
                    if bytes.is_empty() {
                        Ok(None)
                    } else if bytes.len() == DEPOSIT_COUNT_RESPONSE_BYTES {
                        let mut array = [0; 8];
                        array.copy_from_slice(&bytes[32 + 32..32 + 32 + 8]);
                        Ok(Some(u64::from_le_bytes(array)))
                    } else {
                        Err(format!(
                            "Deposit count response was not {} bytes: {:?}",
                            DEPOSIT_COUNT_RESPONSE_BYTES, bytes
                        ))
                    }
                }
            }
        }

        /// Returns the value of the `get_hash_tree_root()` call at the given `block_number`.
        ///
        /// Assumes that the `address` has the same ABI as the eth2 deposit contract.
        pub async fn get_deposit_root(
            &self,
            address: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<Hash256>, String> {
            let result = self
                .call(address, DEPOSIT_ROOT_FN_SIGNATURE, block_number, timeout)
                .await?;
            match result {
                None => Err("Deposit root response was none".to_string()),
                Some(bytes) => {
                    if bytes.is_empty() {
                        Ok(None)
                    } else if bytes.len() == DEPOSIT_ROOT_BYTES {
                        Ok(Some(Hash256::from_slice(&bytes)))
                    } else {
                        Err(format!(
                            "Deposit root response was not {} bytes: {:?}",
                            DEPOSIT_ROOT_BYTES, bytes
                        ))
                    }
                }
            }
        }

        /// Performs a instant, no-transaction call to the contract `address` with the given `0x`-prefixed
        /// `hex_data`.
        ///
        /// Returns bytes, if any.
        async fn call(
            &self,
            address: &str,
            hex_data: &str,
            block_number: u64,
            timeout: Duration,
        ) -> Result<Option<Vec<u8>>, String> {
            let params = json! ([
                {
                    "to": address,
                    "data": hex_data,
                },
                format!("0x{:x}", block_number)
            ]);

            let response: Option<String> = self
                .rpc_request("eth_call", params, timeout)
                .await
                .map_err(|e| format!("eth_call call failed {:?}", e))?;

            response.map(|s| hex_to_bytes(&s)).transpose()
        }

        /// Returns logs for the `DEPOSIT_EVENT_TOPIC`, for the given `address` in the given
        /// `block_height_range`.
        ///
        /// It's not clear from the Ethereum JSON-RPC docs if this range is inclusive or not.
        pub async fn get_deposit_logs_in_range(
            &self,
            address: &str,
            block_height_range: Range<u64>,
            timeout: Duration,
        ) -> Result<Vec<Log>, String> {
            let params = json! ([{
                "address": address,
                "topics": [DEPOSIT_EVENT_TOPIC],
                "fromBlock": format!("0x{:x}", block_height_range.start),
                "toBlock": format!("0x{:x}", block_height_range.end),
            }]);

            let response: Value = self
                .rpc_request("eth_getLogs", params, timeout)
                .await
                .map_err(|e| format!("eth_getLogs call failed {:?}", e))?;
            response
                .as_array()
                .cloned()
                .ok_or("'result' value was not an array")?
                .into_iter()
                .map(|value| {
                    let block_number = value
                        .get("blockNumber")
                        .ok_or("No block number field in log")?
                        .as_str()
                        .ok_or("Block number was not string")?;

                    let data = value
                        .get("data")
                        .ok_or("No block number field in log")?
                        .as_str()
                        .ok_or("Data was not string")?;

                    Ok(Log {
                        block_number: hex_to_u64_be(block_number)?,
                        data: hex_to_bytes(data)?,
                    })
                })
                .collect::<Result<Vec<Log>, String>>()
                .map_err(|e| format!("Failed to get logs in range: {}", e))
        }
    }
}

pub struct CachedResponse<T: Clone> {
    pub data: T,
    pub fetch_time: Instant,
}

impl<T: Clone> CachedResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            data,
            fetch_time: Instant::now(),
        }
    }

    pub fn data(&self) -> T {
        self.data.clone()
    }

    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.fetch_time)
    }

    /// returns `true` if the entry's age is >= age_limit
    pub fn older_than(&self, age_limit: Option<Duration>) -> bool {
        age_limit.map_or(false, |limit| self.age() >= limit)
    }
}

pub struct HttpJsonRpc {
    pub client: Client,
    pub url: SensitiveUrl,
    pub execution_timeout_multiplier: u32,
    pub engine_capabilities_cache: Mutex<Option<CachedResponse<EngineCapabilities>>>,
    pub engine_version_cache: Mutex<Option<CachedResponse<Vec<ClientVersionV1>>>>,
    auth: Option<Auth>,
}

impl HttpJsonRpc {
    pub fn new(
        url: SensitiveUrl,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: Client::builder().build()?,
            url,
            execution_timeout_multiplier: execution_timeout_multiplier.unwrap_or(1),
            engine_capabilities_cache: Mutex::new(None),
            engine_version_cache: Mutex::new(None),
            auth: None,
        })
    }

    pub fn new_with_auth(
        url: SensitiveUrl,
        auth: Auth,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: Client::builder().build()?,
            url,
            execution_timeout_multiplier: execution_timeout_multiplier.unwrap_or(1),
            engine_capabilities_cache: Mutex::new(None),
            engine_version_cache: Mutex::new(None),
            auth: Some(auth),
        })
    }

    pub async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<D, Error> {
        let body = JsonRequestBody {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: json!(STATIC_ID),
        };

        let mut request = self
            .client
            .post(self.url.full.clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        // Generate and add a jwt token to the header if auth is defined.
        if let Some(auth) = &self.auth {
            request = request.bearer_auth(auth.generate_token()?);
        };

        let body: JsonResponseBody = request.send().await?.error_for_status()?.json().await?;

        match (body.result, body.error) {
            (result, None) => serde_json::from_value(result).map_err(Into::into),
            (_, Some(error)) => {
                if error.message.contains(EIP155_ERROR_STR) {
                    Err(Error::Eip155Failure)
                } else {
                    Err(Error::ServerMessage {
                        code: error.code,
                        message: error.message,
                    })
                }
            }
        }
    }
}

impl std::fmt::Display for HttpJsonRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, auth={}", self.url, self.auth.is_some())
    }
}

impl HttpJsonRpc {
    pub async fn upcheck(&self) -> Result<(), Error> {
        let result: serde_json::Value = self
            .rpc_request(
                ETH_SYNCING,
                json!([]),
                ETH_SYNCING_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        /*
         * TODO
         *
         * Check the network and chain ids. We omit this to save time for the merge f2f and since it
         * also seems like it might get annoying during development.
         */
        match result.as_bool() {
            Some(false) => Ok(()),
            _ => Err(Error::IsSyncing),
        }
    }

    pub async fn get_block_by_number<'a>(
        &self,
        query: BlockByNumberQuery<'a>,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([query, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(
            ETH_GET_BLOCK_BY_NUMBER,
            params,
            ETH_GET_BLOCK_BY_NUMBER_TIMEOUT * self.execution_timeout_multiplier,
        )
        .await
    }

    pub async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, Error> {
        let params = json!([block_hash, RETURN_FULL_TRANSACTION_OBJECTS]);

        self.rpc_request(
            ETH_GET_BLOCK_BY_HASH,
            params,
            ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
        )
        .await
    }

    pub async fn get_block_by_hash_with_txns<E: EthSpec>(
        &self,
        block_hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionBlockWithTransactions<E>>, Error> {
        let params = json!([block_hash, true]);
        Ok(Some(match fork {
            ForkName::Bellatrix => ExecutionBlockWithTransactions::Bellatrix(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Capella => ExecutionBlockWithTransactions::Capella(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Deneb => ExecutionBlockWithTransactions::Deneb(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Electra => ExecutionBlockWithTransactions::Electra(
                self.rpc_request(
                    ETH_GET_BLOCK_BY_HASH,
                    params,
                    ETH_GET_BLOCK_BY_HASH_TIMEOUT * self.execution_timeout_multiplier,
                )
                .await?,
            ),
            ForkName::Base | ForkName::Altair => {
                return Err(Error::UnsupportedForkVariant(format!(
                    "called get_block_by_hash_with_txns with fork {:?}",
                    fork
                )))
            }
        }))
    }

    pub async fn new_payload_v1<E: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<E>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V1,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn new_payload_v2<E: EthSpec>(
        &self,
        execution_payload: ExecutionPayload<E>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([JsonExecutionPayload::from(execution_payload)]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V2,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn new_payload_v3_deneb<E: EthSpec>(
        &self,
        new_payload_request_deneb: NewPayloadRequestDeneb<'_, E>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([
            JsonExecutionPayload::V3(new_payload_request_deneb.execution_payload.clone().into()),
            new_payload_request_deneb.versioned_hashes,
            new_payload_request_deneb.parent_beacon_block_root,
        ]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V3,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn new_payload_v4_electra<E: EthSpec>(
        &self,
        new_payload_request_electra: NewPayloadRequestElectra<'_, E>,
    ) -> Result<PayloadStatusV1, Error> {
        let params = json!([
            JsonExecutionPayload::V4(new_payload_request_electra.execution_payload.clone().into()),
            new_payload_request_electra.versioned_hashes,
            new_payload_request_electra.parent_beacon_block_root,
        ]);

        let response: JsonPayloadStatusV1 = self
            .rpc_request(
                ENGINE_NEW_PAYLOAD_V4,
                params,
                ENGINE_NEW_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn get_payload_v1<E: EthSpec>(
        &self,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        let payload_v1: JsonExecutionPayloadV1<E> = self
            .rpc_request(
                ENGINE_GET_PAYLOAD_V1,
                params,
                ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(GetPayloadResponse::Bellatrix(GetPayloadResponseBellatrix {
            execution_payload: payload_v1.into(),
            // Set the V1 payload values from the EE to be zero. This simulates
            // the pre-block-value functionality of always choosing the builder
            // block.
            block_value: Uint256::zero(),
        }))
    }

    pub async fn get_payload_v2<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        match fork_name {
            ForkName::Bellatrix => {
                let response: JsonGetPayloadResponseV1<E> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V2,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V1(response).into())
            }
            ForkName::Capella => {
                let response: JsonGetPayloadResponseV2<E> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V2,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V2(response).into())
            }
            ForkName::Base | ForkName::Altair | ForkName::Deneb | ForkName::Electra => Err(
                Error::UnsupportedForkVariant(format!("called get_payload_v2 with {}", fork_name)),
            ),
        }
    }

    pub async fn get_payload_v3<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        match fork_name {
            ForkName::Deneb => {
                let response: JsonGetPayloadResponseV3<E> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V3,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V3(response).into())
            }
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Electra => Err(Error::UnsupportedForkVariant(format!(
                "called get_payload_v3 with {}",
                fork_name
            ))),
        }
    }

    pub async fn get_payload_v4<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let params = json!([JsonPayloadIdRequest::from(payload_id)]);

        match fork_name {
            ForkName::Electra => {
                let response: JsonGetPayloadResponseV4<E> = self
                    .rpc_request(
                        ENGINE_GET_PAYLOAD_V4,
                        params,
                        ENGINE_GET_PAYLOAD_TIMEOUT * self.execution_timeout_multiplier,
                    )
                    .await?;
                Ok(JsonGetPayloadResponse::V4(response).into())
            }
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => Err(Error::UnsupportedForkVariant(format!(
                "called get_payload_v4 with {}",
                fork_name
            ))),
        }
    }

    pub async fn forkchoice_updated_v1(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let params = json!([
            JsonForkchoiceStateV1::from(forkchoice_state),
            payload_attributes.map(JsonPayloadAttributes::from)
        ]);

        let response: JsonForkchoiceUpdatedV1Response = self
            .rpc_request(
                ENGINE_FORKCHOICE_UPDATED_V1,
                params,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn forkchoice_updated_v2(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let params = json!([
            JsonForkchoiceStateV1::from(forkchoice_state),
            payload_attributes.map(JsonPayloadAttributes::from)
        ]);

        let response: JsonForkchoiceUpdatedV1Response = self
            .rpc_request(
                ENGINE_FORKCHOICE_UPDATED_V2,
                params,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn forkchoice_updated_v3(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let params = json!([
            JsonForkchoiceStateV1::from(forkchoice_state),
            payload_attributes.map(JsonPayloadAttributes::from)
        ]);

        let response: JsonForkchoiceUpdatedV1Response = self
            .rpc_request(
                ENGINE_FORKCHOICE_UPDATED_V3,
                params,
                ENGINE_FORKCHOICE_UPDATED_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response.into())
    }

    pub async fn get_payload_bodies_by_hash_v1<E: EthSpec>(
        &self,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
        let params = json!([block_hashes]);

        let response: Vec<Option<JsonExecutionPayloadBodyV1<E>>> = self
            .rpc_request(
                ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1,
                params,
                ENGINE_GET_PAYLOAD_BODIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response
            .into_iter()
            .map(|opt_json| opt_json.map(From::from))
            .collect())
    }

    pub async fn get_payload_bodies_by_range_v1<E: EthSpec>(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct Quantity(#[serde(with = "serde_utils::u64_hex_be")] u64);

        let params = json!([Quantity(start), Quantity(count)]);
        let response: Vec<Option<JsonExecutionPayloadBodyV1<E>>> = self
            .rpc_request(
                ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1,
                params,
                ENGINE_GET_PAYLOAD_BODIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(response
            .into_iter()
            .map(|opt_json| opt_json.map(From::from))
            .collect())
    }

    pub async fn exchange_capabilities(&self) -> Result<EngineCapabilities, Error> {
        let params = json!([LIGHTHOUSE_CAPABILITIES]);

        let capabilities: HashSet<String> = self
            .rpc_request(
                ENGINE_EXCHANGE_CAPABILITIES,
                params,
                ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        Ok(EngineCapabilities {
            new_payload_v1: capabilities.contains(ENGINE_NEW_PAYLOAD_V1),
            new_payload_v2: capabilities.contains(ENGINE_NEW_PAYLOAD_V2),
            new_payload_v3: capabilities.contains(ENGINE_NEW_PAYLOAD_V3),
            new_payload_v4: capabilities.contains(ENGINE_NEW_PAYLOAD_V4),
            forkchoice_updated_v1: capabilities.contains(ENGINE_FORKCHOICE_UPDATED_V1),
            forkchoice_updated_v2: capabilities.contains(ENGINE_FORKCHOICE_UPDATED_V2),
            forkchoice_updated_v3: capabilities.contains(ENGINE_FORKCHOICE_UPDATED_V3),
            get_payload_bodies_by_hash_v1: capabilities
                .contains(ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1),
            get_payload_bodies_by_range_v1: capabilities
                .contains(ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1),
            get_payload_v1: capabilities.contains(ENGINE_GET_PAYLOAD_V1),
            get_payload_v2: capabilities.contains(ENGINE_GET_PAYLOAD_V2),
            get_payload_v3: capabilities.contains(ENGINE_GET_PAYLOAD_V3),
            get_payload_v4: capabilities.contains(ENGINE_GET_PAYLOAD_V4),
            get_client_version_v1: capabilities.contains(ENGINE_GET_CLIENT_VERSION_V1),
        })
    }

    pub async fn clear_exchange_capabilties_cache(&self) {
        *self.engine_capabilities_cache.lock().await = None;
    }

    /// Returns the execution engine capabilities resulting from a call to
    /// engine_exchangeCapabilities. If the capabilities cache is not populated,
    /// or if it is populated with a cached result of age >= `age_limit`, this
    /// method will fetch the result from the execution engine and populate the
    /// cache before returning it. Otherwise it will return a cached result from
    /// a previous call.
    ///
    /// Set `age_limit` to `None` to always return the cached result
    /// Set `age_limit` to `Some(Duration::ZERO)` to force fetching from EE
    pub async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, Error> {
        let mut lock = self.engine_capabilities_cache.lock().await;

        if let Some(lock) = lock
            .as_ref()
            .filter(|cached_response| !cached_response.older_than(age_limit))
        {
            Ok(lock.data())
        } else {
            let engine_capabilities = self.exchange_capabilities().await?;
            *lock = Some(CachedResponse::new(engine_capabilities));
            Ok(engine_capabilities)
        }
    }

    /// This method fetches the response from the engine without checking
    /// any caches or storing the result in the cache. It is better to use
    /// `get_engine_version(Some(Duration::ZERO))` if you want to force
    /// fetching from the EE as this will cache the result.
    pub async fn get_client_version_v1(&self) -> Result<Vec<ClientVersionV1>, Error> {
        let params = json!([*LIGHTHOUSE_JSON_CLIENT_VERSION]);

        let response: Vec<JsonClientVersionV1> = self
            .rpc_request(
                ENGINE_GET_CLIENT_VERSION_V1,
                params,
                ENGINE_GET_CLIENT_VERSION_TIMEOUT * self.execution_timeout_multiplier,
            )
            .await?;

        response
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidClientVersion)
    }

    pub async fn clear_engine_version_cache(&self) {
        *self.engine_version_cache.lock().await = None;
    }

    /// Returns the execution engine version resulting from a call to
    /// engine_getClientVersionV1. If the version cache is not populated, or if it
    /// is populated with a cached result of age >= `age_limit`, this method will
    /// fetch the result from the execution engine and populate the cache before
    /// returning it. Otherwise it will return the cached result from an earlier
    /// call.
    ///
    /// Set `age_limit` to `None` to always return the cached result
    /// Set `age_limit` to `Some(Duration::ZERO)` to force fetching from EE
    pub async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, Error> {
        // check engine capabilities first (avoids holding two locks at once)
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        if !engine_capabilities.get_client_version_v1 {
            // We choose an empty vec to denote that this method is not
            // supported instead of an error since this method is optional
            // & we don't want to log a warning and concern the user
            return Ok(vec![]);
        }
        let mut lock = self.engine_version_cache.lock().await;
        if let Some(lock) = lock
            .as_ref()
            .filter(|cached_response| !cached_response.older_than(age_limit))
        {
            Ok(lock.data())
        } else {
            let engine_version = self.get_client_version_v1().await?;
            *lock = Some(CachedResponse::new(engine_version.clone()));
            Ok(engine_version)
        }
    }

    // automatically selects the latest version of
    // new_payload that the execution engine supports
    pub async fn new_payload<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, Error> {
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        match new_payload_request {
            NewPayloadRequest::Bellatrix(_) | NewPayloadRequest::Capella(_) => {
                if engine_capabilities.new_payload_v2 {
                    self.new_payload_v2(new_payload_request.into_execution_payload())
                        .await
                } else if engine_capabilities.new_payload_v1 {
                    self.new_payload_v1(new_payload_request.into_execution_payload())
                        .await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_newPayload"))
                }
            }
            NewPayloadRequest::Deneb(new_payload_request_deneb) => {
                if engine_capabilities.new_payload_v3 {
                    self.new_payload_v3_deneb(new_payload_request_deneb).await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_newPayloadV3"))
                }
            }
            NewPayloadRequest::Electra(new_payload_request_electra) => {
                if engine_capabilities.new_payload_v4 {
                    self.new_payload_v4_electra(new_payload_request_electra)
                        .await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_newPayloadV4"))
                }
            }
        }
    }

    // automatically selects the latest version of
    // get_payload that the execution engine supports
    pub async fn get_payload<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        match fork_name {
            ForkName::Bellatrix | ForkName::Capella => {
                if engine_capabilities.get_payload_v2 {
                    self.get_payload_v2(fork_name, payload_id).await
                } else if engine_capabilities.get_payload_v1 {
                    self.get_payload_v1(payload_id).await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_getPayload"))
                }
            }
            ForkName::Deneb => {
                if engine_capabilities.get_payload_v3 {
                    self.get_payload_v3(fork_name, payload_id).await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_getPayloadv3"))
                }
            }
            ForkName::Electra => {
                if engine_capabilities.get_payload_v4 {
                    self.get_payload_v4(fork_name, payload_id).await
                } else {
                    Err(Error::RequiredMethodUnsupported("engine_getPayloadv4"))
                }
            }
            ForkName::Base | ForkName::Altair => Err(Error::UnsupportedForkVariant(format!(
                "called get_payload with {}",
                fork_name
            ))),
        }
    }

    // automatically selects the latest version of
    // forkchoice_updated that the execution engine supports
    pub async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        maybe_payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let engine_capabilities = self.get_engine_capabilities(None).await?;
        if let Some(payload_attributes) = maybe_payload_attributes.as_ref() {
            match payload_attributes {
                PayloadAttributes::V1(_) | PayloadAttributes::V2(_) => {
                    if engine_capabilities.forkchoice_updated_v2 {
                        self.forkchoice_updated_v2(forkchoice_state, maybe_payload_attributes)
                            .await
                    } else if engine_capabilities.forkchoice_updated_v1 {
                        self.forkchoice_updated_v1(forkchoice_state, maybe_payload_attributes)
                            .await
                    } else {
                        Err(Error::RequiredMethodUnsupported("engine_forkchoiceUpdated"))
                    }
                }
                PayloadAttributes::V3(_) => {
                    if engine_capabilities.forkchoice_updated_v3 {
                        self.forkchoice_updated_v3(forkchoice_state, maybe_payload_attributes)
                            .await
                    } else {
                        Err(Error::RequiredMethodUnsupported(
                            "engine_forkchoiceUpdatedV3",
                        ))
                    }
                }
            }
        } else if engine_capabilities.forkchoice_updated_v3 {
            self.forkchoice_updated_v3(forkchoice_state, maybe_payload_attributes)
                .await
        } else if engine_capabilities.forkchoice_updated_v2 {
            self.forkchoice_updated_v2(forkchoice_state, maybe_payload_attributes)
                .await
        } else if engine_capabilities.forkchoice_updated_v1 {
            self.forkchoice_updated_v1(forkchoice_state, maybe_payload_attributes)
                .await
        } else {
            Err(Error::RequiredMethodUnsupported("engine_forkchoiceUpdated"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::auth::JwtKey;
    use super::*;
    use crate::test_utils::{MockServer, DEFAULT_JWT_SECRET};
    use std::future::Future;
    use std::str::FromStr;
    use std::sync::Arc;
    use types::{MainnetEthSpec, Unsigned};

    struct Tester {
        server: MockServer<MainnetEthSpec>,
        rpc_client: Arc<HttpJsonRpc>,
        echo_client: Arc<HttpJsonRpc>,
    }

    impl Tester {
        pub fn new(with_auth: bool) -> Self {
            let server = MockServer::unit_testing();

            let rpc_url = SensitiveUrl::parse(&server.url()).unwrap();
            let echo_url = SensitiveUrl::parse(&format!("{}/echo", server.url())).unwrap();
            // Create rpc clients that include JWT auth headers if `with_auth` is true.
            let (rpc_client, echo_client) = if with_auth {
                let rpc_auth =
                    Auth::new(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(), None, None);
                let echo_auth =
                    Auth::new(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(), None, None);
                (
                    Arc::new(HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap()),
                    Arc::new(HttpJsonRpc::new_with_auth(echo_url, echo_auth, None).unwrap()),
                )
            } else {
                (
                    Arc::new(HttpJsonRpc::new(rpc_url, None).unwrap()),
                    Arc::new(HttpJsonRpc::new(echo_url, None).unwrap()),
                )
            };

            Self {
                server,
                rpc_client,
                echo_client,
            }
        }

        pub async fn assert_request_equals<R, F>(
            self,
            request_func: R,
            expected_json: serde_json::Value,
        ) -> Self
        where
            R: Fn(Arc<HttpJsonRpc>) -> F,
            F: Future<Output = ()>,
        {
            request_func(self.echo_client.clone()).await;
            let request_bytes = self.server.last_echo_request();
            let request_json: serde_json::Value =
                serde_json::from_slice(&request_bytes).expect("request was not valid json");
            if request_json != expected_json {
                panic!(
                    "json mismatch!\n\nobserved: {}\n\nexpected: {}\n\n",
                    request_json, expected_json,
                )
            }
            self
        }

        pub async fn assert_auth_failure<R, F, T>(self, request_func: R) -> Self
        where
            R: Fn(Arc<HttpJsonRpc>) -> F,
            F: Future<Output = Result<T, Error>>,
            T: std::fmt::Debug,
        {
            let res = request_func(self.echo_client.clone()).await;
            if !matches!(res, Err(Error::Auth(_))) {
                panic!(
                    "No authentication provided, rpc call should have failed.\nResult: {:?}",
                    res
                )
            }
            self
        }

        pub async fn with_preloaded_responses<R, F>(
            self,
            preloaded_responses: Vec<serde_json::Value>,
            request_func: R,
        ) -> Self
        where
            R: Fn(Arc<HttpJsonRpc>) -> F,
            F: Future<Output = ()>,
        {
            for response in preloaded_responses {
                self.server.push_preloaded_response(response);
            }
            request_func(self.rpc_client.clone()).await;
            self
        }
    }

    const HASH_00: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_01: &str = "0x0101010101010101010101010101010101010101010101010101010101010101";

    const ADDRESS_00: &str = "0x0000000000000000000000000000000000000000";
    const ADDRESS_01: &str = "0x0101010101010101010101010101010101010101";

    const JSON_NULL: serde_json::Value = serde_json::Value::Null;
    const LOGS_BLOOM_00: &str = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const LOGS_BLOOM_01: &str = "0x01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101";

    fn encode_transactions<E: EthSpec>(
        transactions: Transactions<E>,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let ep: JsonExecutionPayload<E> = JsonExecutionPayload::V1(JsonExecutionPayloadV1 {
            transactions,
            ..<_>::default()
        });
        let json = serde_json::to_value(ep)?;
        Ok(json.get("transactions").unwrap().clone())
    }

    fn decode_transactions<E: EthSpec>(
        transactions: serde_json::Value,
    ) -> Result<Transactions<E>, serde_json::Error> {
        let mut json = json!({
            "parentHash": HASH_00,
            "feeRecipient": ADDRESS_01,
            "stateRoot": HASH_01,
            "receiptsRoot": HASH_00,
            "logsBloom": LOGS_BLOOM_01,
            "prevRandao": HASH_01,
            "blockNumber": "0x0",
            "gasLimit": "0x1",
            "gasUsed": "0x2",
            "timestamp": "0x2a",
            "extraData": "0x",
            "baseFeePerGas": "0x1",
            "blockHash": HASH_01,
        });
        // Take advantage of the fact that we own `transactions` and don't need to reserialize it.
        json.as_object_mut()
            .unwrap()
            .insert("transactions".into(), transactions);
        let ep: JsonExecutionPayload<E> = serde_json::from_value(json)?;
        Ok(ep.transactions().clone())
    }

    fn assert_transactions_serde<E: EthSpec>(
        name: &str,
        as_obj: Transactions<E>,
        as_json: serde_json::Value,
    ) {
        assert_eq!(
            encode_transactions::<E>(as_obj.clone()).unwrap(),
            as_json,
            "encoding for {}",
            name
        );
        assert_eq!(
            decode_transactions::<E>(as_json).unwrap(),
            as_obj,
            "decoding for {}",
            name
        );
    }

    /// Example: if `spec == &[1, 1]`, then two one-byte transactions will be created.
    fn generate_transactions<E: EthSpec>(spec: &[usize]) -> Transactions<E> {
        let mut txs = VariableList::default();

        for &num_bytes in spec {
            let mut tx = VariableList::default();
            for _ in 0..num_bytes {
                tx.push(0).unwrap();
            }
            txs.push(tx).unwrap();
        }

        txs
    }

    #[test]
    fn transaction_serde() {
        assert_transactions_serde::<MainnetEthSpec>(
            "empty",
            generate_transactions::<MainnetEthSpec>(&[]),
            json!([]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one empty tx",
            generate_transactions::<MainnetEthSpec>(&[0]),
            json!(["0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two empty txs",
            generate_transactions::<MainnetEthSpec>(&[0, 0]),
            json!(["0x", "0x"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "one one-byte tx",
            generate_transactions::<MainnetEthSpec>(&[1]),
            json!(["0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "two one-byte txs",
            generate_transactions::<MainnetEthSpec>(&[1, 1]),
            json!(["0x00", "0x00"]),
        );
        assert_transactions_serde::<MainnetEthSpec>(
            "mixed bag",
            generate_transactions::<MainnetEthSpec>(&[0, 1, 3, 0]),
            json!(["0x", "0x00", "0x000000", "0x"]),
        );

        /*
         * Check for too many transactions
         */

        let num_max_txs = <MainnetEthSpec as EthSpec>::MaxTransactionsPerPayload::to_usize();
        let max_txs = (0..num_max_txs).map(|_| "0x00").collect::<Vec<_>>();
        let too_many_txs = (0..=num_max_txs).map(|_| "0x00").collect::<Vec<_>>();

        decode_transactions::<MainnetEthSpec>(serde_json::to_value(max_txs).unwrap()).unwrap();
        assert!(
            decode_transactions::<MainnetEthSpec>(serde_json::to_value(too_many_txs).unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_block_by_number_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ETH_GET_BLOCK_BY_NUMBER,
                    "params": ["latest", false]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client
                    .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                    .await
            })
            .await;
    }

    #[tokio::test]
    async fn get_block_by_hash_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .get_block_by_hash(ExecutionBlockHash::repeat_byte(1))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ETH_GET_BLOCK_BY_HASH,
                    "params": [HASH_01, false]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client
                    .get_block_by_hash(ExecutionBlockHash::repeat_byte(1))
                    .await
            })
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_v1_with_payload_attributes_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::repeat_byte(1),
                                safe_block_hash: ExecutionBlockHash::repeat_byte(1),
                                finalized_block_hash: ExecutionBlockHash::zero(),
                            },
                            Some(PayloadAttributes::V1(PayloadAttributesV1 {
                                timestamp: 5,
                                prev_randao: Hash256::zero(),
                                suggested_fee_recipient: Address::repeat_byte(0),
                            })),
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": HASH_01,
                        "safeBlockHash": HASH_01,
                        "finalizedBlockHash": HASH_00,
                    },
                    {
                        "timestamp":"0x5",
                        "prevRandao": HASH_00,
                        "suggestedFeeRecipient": ADDRESS_00
                    }]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client
                    .forkchoice_updated_v1(
                        ForkchoiceState {
                            head_block_hash: ExecutionBlockHash::repeat_byte(1),
                            safe_block_hash: ExecutionBlockHash::repeat_byte(1),
                            finalized_block_hash: ExecutionBlockHash::zero(),
                        },
                        Some(PayloadAttributes::V1(PayloadAttributesV1 {
                            timestamp: 5,
                            prev_randao: Hash256::zero(),
                            suggested_fee_recipient: Address::repeat_byte(0),
                        })),
                    )
                    .await
            })
            .await;
    }

    #[tokio::test]
    async fn get_payload_v1_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client.get_payload_v1::<MainnetEthSpec>([42; 8]).await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_GET_PAYLOAD_V1,
                    "params": ["0x2a2a2a2a2a2a2a2a"]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client.get_payload_v1::<MainnetEthSpec>([42; 8]).await
            })
            .await;
    }

    #[tokio::test]
    async fn new_payload_v1_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .new_payload_v1::<MainnetEthSpec>(ExecutionPayload::Bellatrix(
                            ExecutionPayloadBellatrix {
                                parent_hash: ExecutionBlockHash::repeat_byte(0),
                                fee_recipient: Address::repeat_byte(1),
                                state_root: Hash256::repeat_byte(1),
                                receipts_root: Hash256::repeat_byte(0),
                                logs_bloom: vec![1; 256].into(),
                                prev_randao: Hash256::repeat_byte(1),
                                block_number: 0,
                                gas_limit: 1,
                                gas_used: 2,
                                timestamp: 42,
                                extra_data: vec![].into(),
                                base_fee_per_gas: Uint256::from(1),
                                block_hash: ExecutionBlockHash::repeat_byte(1),
                                transactions: vec![].into(),
                            },
                        ))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_NEW_PAYLOAD_V1,
                    "params": [{
                        "parentHash": HASH_00,
                        "feeRecipient": ADDRESS_01,
                        "stateRoot": HASH_01,
                        "receiptsRoot": HASH_00,
                        "logsBloom": LOGS_BLOOM_01,
                        "prevRandao": HASH_01,
                        "blockNumber": "0x0",
                        "gasLimit": "0x1",
                        "gasUsed": "0x2",
                        "timestamp": "0x2a",
                        "extraData": "0x",
                        "baseFeePerGas": "0x1",
                        "blockHash": HASH_01,
                        "transactions": [],
                    }]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client
                    .new_payload_v1::<MainnetEthSpec>(ExecutionPayload::Bellatrix(
                        ExecutionPayloadBellatrix {
                            parent_hash: ExecutionBlockHash::repeat_byte(0),
                            fee_recipient: Address::repeat_byte(1),
                            state_root: Hash256::repeat_byte(1),
                            receipts_root: Hash256::repeat_byte(0),
                            logs_bloom: vec![1; 256].into(),
                            prev_randao: Hash256::repeat_byte(1),
                            block_number: 0,
                            gas_limit: 1,
                            gas_used: 2,
                            timestamp: 42,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(1),
                            block_hash: ExecutionBlockHash::repeat_byte(1),
                            transactions: vec![].into(),
                        },
                    ))
                    .await
            })
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_v1_request() {
        Tester::new(true)
            .assert_request_equals(
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::repeat_byte(0),
                                safe_block_hash: ExecutionBlockHash::repeat_byte(0),
                                finalized_block_hash: ExecutionBlockHash::repeat_byte(1),
                            },
                            None,
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": HASH_00,
                        "safeBlockHash": HASH_00,
                        "finalizedBlockHash": HASH_01,
                    }, JSON_NULL]
                }),
            )
            .await;

        Tester::new(false)
            .assert_auth_failure(|client| async move {
                client
                    .forkchoice_updated_v1(
                        ForkchoiceState {
                            head_block_hash: ExecutionBlockHash::repeat_byte(0),
                            safe_block_hash: ExecutionBlockHash::repeat_byte(0),
                            finalized_block_hash: ExecutionBlockHash::repeat_byte(1),
                        },
                        None,
                    )
                    .await
            })
            .await;
    }

    fn str_to_payload_id(s: &str) -> PayloadId {
        serde_json::from_str::<TransparentJsonPayloadId>(&format!("\"{}\"", s))
            .unwrap()
            .into()
    }

    #[test]
    fn str_payload_id() {
        assert_eq!(
            str_to_payload_id("0x002a2a2a2a2a2a01"),
            [0, 42, 42, 42, 42, 42, 42, 1]
        );
    }

    /// Test vectors provided by Geth:
    ///
    /// https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
    ///
    /// The `id` field has been modified on these vectors to match the one we use.
    #[tokio::test]
    async fn geth_test_vectors() {
        Tester::new(true)
            .assert_request_equals(
                // engine_forkchoiceUpdatedV1 (prepare payload) REQUEST validation
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                safe_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                finalized_block_hash: ExecutionBlockHash::zero(),
                            },
                            Some(PayloadAttributes::V1(PayloadAttributesV1 {
                                timestamp: 5,
                                prev_randao: Hash256::zero(),
                                suggested_fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            }))
                        )
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [{
                        "headBlockHash": "0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "safeBlockHash": "0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "finalizedBlockHash": HASH_00,
                    },
                    {
                        "timestamp":"0x5",
                        "prevRandao": HASH_00,
                        "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                    }]
                })
            )
            .await
            .with_preloaded_responses(
                // engine_forkchoiceUpdatedV1 (prepare payload) RESPONSE validation
                vec![json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "result": {
                        "payloadStatus": {
                            "status": "VALID",
                            "latestValidHash": HASH_00,
                            "validationError": ""
                        },
                        "payloadId": "0xa247243752eb10b4"
                    }
                })],
                |client| async move {
                    let response = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                safe_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                                finalized_block_hash: ExecutionBlockHash::zero(),
                            },
                            Some(PayloadAttributes::V1(PayloadAttributesV1 {
                                timestamp: 5,
                                prev_randao: Hash256::zero(),
                                suggested_fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            }))
                        )
                        .await
                        .unwrap();
                    assert_eq!(response, ForkchoiceUpdatedResponse {
                        payload_status: PayloadStatusV1 {
                            status: PayloadStatusV1Status::Valid,
                            latest_valid_hash: Some(ExecutionBlockHash::zero()),
                            validation_error: Some(String::new()),
                        },
                        payload_id:
                            Some(str_to_payload_id("0xa247243752eb10b4")),
                    });
                },
            )
            .await
            .assert_request_equals(
                // engine_getPayloadV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .get_payload_v1::<MainnetEthSpec>(str_to_payload_id("0xa247243752eb10b4"))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_GET_PAYLOAD_V1,
                    "params": ["0xa247243752eb10b4"]
                })
            )
            .await
            .with_preloaded_responses(
                // engine_getPayloadV1 RESPONSE validation
                vec![json!({
                    "jsonrpc":JSONRPC_VERSION,
                    "id":STATIC_ID,
                    "result":{
                        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
                        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "logsBloom": LOGS_BLOOM_00,
                        "prevRandao": HASH_00,
                        "blockNumber":"0x1",
                        "gasLimit":"0x1c95111",
                        "gasUsed":"0x0",
                        "timestamp":"0x5",
                        "extraData":"0x",
                        "baseFeePerGas":"0x7",
                        "blockHash":"0x6359b8381a370e2f54072a5784ddd78b6ed024991558c511d4452eb4f6ac898c",
                        "transactions":[],
                    }
                })],
                |client| async move {
                    let payload: ExecutionPayload<_> = client
                        .get_payload_v1::<MainnetEthSpec>(str_to_payload_id("0xa247243752eb10b4"))
                        .await
                        .unwrap()
                        .into();

                    let expected = ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix {
                            parent_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipts_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            prev_randao: Hash256::zero(),
                            block_number: 1,
                            gas_limit: u64::from_str_radix("1c95111",16).unwrap(),
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(7),
                            block_hash: ExecutionBlockHash::from_str("0x6359b8381a370e2f54072a5784ddd78b6ed024991558c511d4452eb4f6ac898c").unwrap(),
                            transactions: vec![].into(),
                        });

                    assert_eq!(payload, expected);
                },
            )
            .await
            .assert_request_equals(
                // engine_newPayloadV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .new_payload_v1::<MainnetEthSpec>(ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix{
                            parent_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            fee_recipient: Address::from_str("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap(),
                            state_root: Hash256::from_str("0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45").unwrap(),
                            receipts_root: Hash256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap(),
                            logs_bloom: vec![0; 256].into(),
                            prev_randao: Hash256::zero(),
                            block_number: 1,
                            gas_limit: u64::from_str_radix("1c9c380",16).unwrap(),
                            gas_used: 0,
                            timestamp: 5,
                            extra_data: vec![].into(),
                            base_fee_per_gas: Uint256::from(7),
                            block_hash: ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                            transactions: vec![].into(),
                        }))
                        .await;
                },
                json!({
                    "id": STATIC_ID,
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_NEW_PAYLOAD_V1,
                    "params": [{
                        "parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a",
                        "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                        "stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45",
                        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "logsBloom": LOGS_BLOOM_00,
                        "prevRandao": HASH_00,
                        "blockNumber":"0x1",
                        "gasLimit":"0x1c9c380",
                        "gasUsed":"0x0",
                        "timestamp":"0x5",
                        "extraData":"0x",
                        "baseFeePerGas":"0x7",
                        "blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                        "transactions":[],
                    }],
                })
            )
            .await
            .with_preloaded_responses(
                // engine_newPayloadV1 RESPONSE validation
                vec![json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": STATIC_ID,
                    "result":{
                        "status":"VALID",
                        "latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                        "validationError":"",
                    }
                })],
                |client| async move {
                    let response = client
                        .new_payload_v1::<MainnetEthSpec>(ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix::default()))
                        .await
                        .unwrap();

                    assert_eq!(response,
                               PayloadStatusV1 {
                            status: PayloadStatusV1Status::Valid,
                            latest_valid_hash: Some(ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap()),
                            validation_error: Some(String::new()),
                        }
                    );
                },
            )
            .await
            .assert_request_equals(
                // engine_forkchoiceUpdatedV1 REQUEST validation
                |client| async move {
                    let _ = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                safe_block_hash: ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                finalized_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            },
                            None,
                        )
                        .await;
                },
                json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "method": ENGINE_FORKCHOICE_UPDATED_V1,
                    "params": [
                        {
                            "headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                            "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858",
                            "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"
                        }, JSON_NULL],
                    "id": STATIC_ID
                })
            )
            .await
            .with_preloaded_responses(
                // engine_forkchoiceUpdatedV1 RESPONSE validation
                vec![json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": STATIC_ID,
                    "result": {
                        "payloadStatus": {
                            "status": "VALID",
                            "latestValidHash": HASH_00,
                            "validationError": ""
                        },
                        "payloadId": JSON_NULL,
                    }
                })],
                |client| async move {
                    let response = client
                        .forkchoice_updated_v1(
                            ForkchoiceState {
                                head_block_hash: ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                safe_block_hash: ExecutionBlockHash::from_str("0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858").unwrap(),
                                finalized_block_hash: ExecutionBlockHash::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a").unwrap(),
                            },
                            None,
                        )
                        .await
                        .unwrap();
                    assert_eq!(response, ForkchoiceUpdatedResponse {
                        payload_status: PayloadStatusV1 {
                            status: PayloadStatusV1Status::Valid,
                            latest_valid_hash: Some(ExecutionBlockHash::zero()),
                            validation_error: Some(String::new()),
                        },
                        payload_id: None,
                    });
                },
            )
            .await;
    }
}
