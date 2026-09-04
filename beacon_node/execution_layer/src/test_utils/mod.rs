//! Provides a mock execution engine HTTP JSON-RPC API for use in testing.

use crate::engine_api::auth::JwtKey;
use crate::engine_api::{
    PayloadStatusV1, PayloadStatusV1Status, auth::Auth, http::JSONRPC_VERSION,
};
use crate::json_structures::JsonClientVersionV1;
use bytes::Bytes;
use execution_block_generator::PoWBlock;
use handle_rpc::handle_rpc;
use kzg::Kzg;

use logging::create_test_tracing_subscriber;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, LazyLock};
use tokio::{runtime, sync::oneshot};
use tracing::info;
use types::{EthSpec, ExecutionBlockHash, Uint256};
use warp::{Filter, Rejection, http::StatusCode};

use crate::{EngineCapabilities, ForkchoiceState, JsonRpcCapabilities, PayloadAttributes};
pub use execution_block_generator::DEFAULT_GAS_LIMIT;
pub use execution_block_generator::{
    Block, ExecutionBlockGenerator, generate_blobs, generate_genesis_block,
    generate_genesis_header, generate_pow_block, mock_el_extra_data, static_valid_tx,
};
pub use hook::Hook;
pub use mock_builder::{MockBuilder, Operation, mock_builder_extra_data};
pub use mock_execution_layer::MockExecutionLayer;
pub use mock_execution_layer::mock_rest_ssz_enabled;

pub const DEFAULT_JWT_SECRET: [u8; 32] = [42; 32];
pub const DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI: u128 = 10_000_000_000_000_000;
pub const DEFAULT_BUILDER_PAYLOAD_VALUE_WEI: u128 = 20_000_000_000_000_000;
pub const DEFAULT_JSON_RPC_CAPABILITIES: JsonRpcCapabilities = JsonRpcCapabilities {
    new_payload_v1: true,
    new_payload_v2: true,
    new_payload_v3: true,
    new_payload_v4: true,
    new_payload_v5: true,
    forkchoice_updated_v1: true,
    forkchoice_updated_v2: true,
    forkchoice_updated_v3: true,
    forkchoice_updated_v4: true,
    get_payload_bodies_by_hash_v1: true,
    get_payload_bodies_by_range_v1: true,
    get_payload_v1: true,
    get_payload_v2: true,
    get_payload_v3: true,
    get_payload_v4: true,
    get_payload_v5: true,
    get_payload_v6: true,
    get_client_version_v1: true,
    get_blobs_v2: true,
    get_blobs_v3: true,
    get_inclusion_list_v1: true,
};

pub const DEFAULT_ENGINE_CAPABILITIES: EngineCapabilities =
    EngineCapabilities::JsonRpc(DEFAULT_JSON_RPC_CAPABILITIES);

pub static DEFAULT_CLIENT_VERSION: LazyLock<JsonClientVersionV1> =
    LazyLock::new(|| JsonClientVersionV1 {
        code: "MC".to_string(), // "mock client"
        name: "Mock Execution Client".to_string(),
        version: "0.1.0".to_string(),
        commit: "0xabcdef01".to_string(),
    });

mod execution_block_generator;
mod handle_rest;
mod handle_rpc;
mod hook;
mod mock_builder;
mod mock_engine_core;
mod mock_execution_layer;

/// Configuration for the MockExecutionLayer.
#[derive(Clone)]
pub struct MockExecutionConfig {
    pub server_config: Config,
    pub jwt_key: JwtKey,
    pub shanghai_time: Option<u64>,
    pub cancun_time: Option<u64>,
    pub prague_time: Option<u64>,
    pub osaka_time: Option<u64>,
    pub amsterdam_time: Option<u64>,
    pub serve_rest_ssz: bool,
    pub heze_time: Option<u64>,
}

impl Default for MockExecutionConfig {
    fn default() -> Self {
        Self {
            jwt_key: JwtKey::random(),
            server_config: Config::default(),
            shanghai_time: None,
            cancun_time: None,
            prague_time: None,
            osaka_time: None,
            amsterdam_time: None,
            serve_rest_ssz: false,
            heze_time: None,
        }
    }
}

pub struct MockServer<E: EthSpec> {
    _shutdown_tx: oneshot::Sender<()>,
    listen_socket_addr: SocketAddr,
    last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub ctx: Arc<Context<E>>,
}

impl<E: EthSpec> MockServer<E> {
    pub fn unit_testing() -> Self {
        Self::new(
            &runtime::Handle::current(),
            JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(),
            None, // FIXME(capella): should this be the default?
            None, // FIXME(deneb): should this be the default?
            None, // FIXME(electra): should this be the default?
            None, // FIXME(fulu): should this be the default?
            None, // FIXME(gloas): should this be the default?
            None, // FIXME(heze): should this be the default?
            None,
        )
    }

    pub fn new_with_config(
        handle: &runtime::Handle,
        config: MockExecutionConfig,
        kzg: Option<Arc<Kzg>>,
    ) -> Self {
        create_test_tracing_subscriber();
        let MockExecutionConfig {
            jwt_key,
            server_config,
            shanghai_time,
            cancun_time,
            prague_time,
            osaka_time,
            amsterdam_time,
            serve_rest_ssz,
            heze_time,
        } = config;
        let last_echo_request = Arc::new(RwLock::new(None));
        let preloaded_responses = Arc::new(Mutex::new(vec![]));
        let execution_block_generator = ExecutionBlockGenerator::new(
            shanghai_time,
            cancun_time,
            prague_time,
            osaka_time,
            amsterdam_time,
            heze_time,
            kzg,
        );

        let ctx: Arc<Context<E>> = Arc::new(Context {
            config: server_config,
            jwt_key,
            last_echo_request: last_echo_request.clone(),
            last_rest_request: <_>::default(),
            serve_rest_ssz,
            execution_block_generator: RwLock::new(execution_block_generator),
            previous_request: <_>::default(),
            previous_forkchoice_request: <_>::default(),
            preloaded_responses,
            static_new_payload_response: <_>::default(),
            static_forkchoice_updated_response: <_>::default(),
            hook: <_>::default(),
            new_payload_statuses: <_>::default(),
            fcu_payload_statuses: <_>::default(),
            syncing_response: Arc::new(Mutex::new(Ok(false))),
            engine_capabilities: Arc::new(RwLock::new(DEFAULT_ENGINE_CAPABILITIES)),
            _phantom: PhantomData,
        });

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let shutdown_future = async {
            // Ignore the result from the channel, shut down regardless.
            let _ = shutdown_rx.await;
        };

        // The `serve` function will panic unless it's run inside a tokio runtime, so use `block_on`
        // if we're not in a runtime. However, we can't *always* use `block_on` since tokio will
        // panic if we try to block inside an async context.
        let serve = || serve(ctx.clone(), shutdown_future).unwrap();
        let (listen_socket_addr, server_future) = if runtime::Handle::try_current().is_err() {
            handle.block_on(async { serve() })
        } else {
            serve()
        };

        handle.spawn(server_future);

        Self {
            _shutdown_tx: shutdown_tx,
            listen_socket_addr,
            last_echo_request,
            ctx,
        }
    }

    pub fn set_engine_capabilities(&self, engine_capabilities: EngineCapabilities) {
        *self.ctx.engine_capabilities.write() = engine_capabilities;
    }

    pub fn disable_client_version(&self) {
        match &mut *self.ctx.engine_capabilities.write() {
            EngineCapabilities::JsonRpc(capabilities) => {
                capabilities.get_client_version_v1 = false;
            }
            EngineCapabilities::Ssz(capabilities) => {
                capabilities
                    .unscoped_endpoints
                    .retain(|e| e.as_str() != "identity");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle: &runtime::Handle,
        jwt_key: JwtKey,
        shanghai_time: Option<u64>,
        cancun_time: Option<u64>,
        prague_time: Option<u64>,
        osaka_time: Option<u64>,
        amsterdam_time: Option<u64>,
        heze_time: Option<u64>,
        kzg: Option<Arc<Kzg>>,
    ) -> Self {
        Self::new_with_config(
            handle,
            MockExecutionConfig {
                server_config: Config::default(),
                jwt_key,
                shanghai_time,
                cancun_time,
                prague_time,
                osaka_time,
                amsterdam_time,
                serve_rest_ssz: false,
                heze_time,
            },
            kzg,
        )
    }

    pub fn execution_block_generator(&self) -> RwLockWriteGuard<'_, ExecutionBlockGenerator<E>> {
        self.ctx.execution_block_generator.write()
    }

    pub fn expire_all_payload_ids(&self) {
        self.ctx
            .execution_block_generator
            .write()
            .expire_all_payload_ids();
    }

    pub fn url(&self) -> String {
        format!(
            "http://{}:{}",
            self.listen_socket_addr.ip(),
            self.listen_socket_addr.port()
        )
    }

    pub fn last_echo_request(&self) -> Bytes {
        self.last_echo_request
            .write()
            .take()
            .expect("last echo request is none")
    }

    pub fn last_rest_request(&self) -> RestCapture {
        self.ctx
            .last_rest_request
            .write()
            .take()
            .expect("last rest request is none")
    }

    pub fn push_preloaded_response(&self, response: serde_json::Value) {
        self.ctx.preloaded_responses.lock().push(response)
    }

    pub fn take_previous_request(&self) -> Option<serde_json::Value> {
        self.ctx.previous_request.lock().take()
    }

    pub fn take_previous_forkchoice_request(&self) -> Option<CapturedForkchoiceRequest> {
        self.ctx.previous_forkchoice_request.lock().take()
    }

    pub fn set_new_payload_response(&self, response: StaticNewPayloadResponse) {
        *self.ctx.static_new_payload_response.lock() = Some(response)
    }

    pub fn set_forkchoice_updated_response(&self, status: PayloadStatusV1) {
        *self.ctx.static_forkchoice_updated_response.lock() = Some(status);
    }

    fn valid_status() -> PayloadStatusV1 {
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: None,
            validation_error: None,
        }
    }

    fn valid_new_payload_response() -> StaticNewPayloadResponse {
        StaticNewPayloadResponse {
            status: Self::valid_status(),
            should_import: true,
        }
    }

    fn syncing_status() -> PayloadStatusV1 {
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Syncing,
            latest_valid_hash: None,
            validation_error: None,
        }
    }

    fn syncing_new_payload_response(should_import: bool) -> StaticNewPayloadResponse {
        StaticNewPayloadResponse {
            status: Self::syncing_status(),
            should_import,
        }
    }

    fn invalid_status(latest_valid_hash: ExecutionBlockHash) -> PayloadStatusV1 {
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Invalid,
            latest_valid_hash: Some(latest_valid_hash),
            validation_error: Some("static response".into()),
        }
    }

    fn invalid_new_payload_response(
        latest_valid_hash: ExecutionBlockHash,
    ) -> StaticNewPayloadResponse {
        StaticNewPayloadResponse {
            status: Self::invalid_status(latest_valid_hash),
            should_import: true,
        }
    }

    fn invalid_block_hash_status() -> PayloadStatusV1 {
        PayloadStatusV1 {
            status: PayloadStatusV1Status::InvalidBlockHash,
            latest_valid_hash: None,
            validation_error: Some("static response".into()),
        }
    }

    fn invalid_block_hash_new_payload_response() -> StaticNewPayloadResponse {
        StaticNewPayloadResponse {
            status: Self::invalid_block_hash_status(),
            should_import: true,
        }
    }

    fn invalid_terminal_block_status() -> PayloadStatusV1 {
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Invalid,
            latest_valid_hash: Some(ExecutionBlockHash::zero()),
            validation_error: Some("static response".into()),
        }
    }

    fn invalid_terminal_block_new_payload_response() -> StaticNewPayloadResponse {
        StaticNewPayloadResponse {
            status: Self::invalid_terminal_block_status(),
            should_import: true,
        }
    }

    pub fn all_payloads_valid(&self) {
        self.all_payloads_valid_on_new_payload();
        self.all_payloads_valid_on_forkchoice_updated();
    }

    pub fn all_payloads_valid_on_new_payload(&self) {
        self.set_new_payload_response(Self::valid_new_payload_response());
    }

    pub fn all_payloads_valid_on_forkchoice_updated(&self) {
        self.set_forkchoice_updated_response(Self::valid_status());
    }

    /// Setting `should_import = true` simulates an EE that initially returns `SYNCING` but obtains
    /// the block via its own means (e.g., devp2p).
    pub fn all_payloads_syncing(&self, should_import: bool) {
        self.all_payloads_syncing_on_new_payload(should_import);
        self.all_payloads_syncing_on_forkchoice_updated();
    }

    pub fn all_payloads_syncing_on_new_payload(&self, should_import: bool) {
        self.set_new_payload_response(Self::syncing_new_payload_response(should_import));
    }

    pub fn all_payloads_syncing_on_forkchoice_updated(&self) {
        self.set_forkchoice_updated_response(Self::syncing_status());
    }

    pub fn all_payloads_invalid(&self, latest_valid_hash: ExecutionBlockHash) {
        self.all_payloads_invalid_on_new_payload(latest_valid_hash);
        self.all_payloads_invalid_on_forkchoice_updated(latest_valid_hash);
    }

    pub fn all_payloads_invalid_on_new_payload(&self, latest_valid_hash: ExecutionBlockHash) {
        self.set_new_payload_response(Self::invalid_new_payload_response(latest_valid_hash));
    }

    pub fn all_payloads_invalid_on_forkchoice_updated(
        &self,
        latest_valid_hash: ExecutionBlockHash,
    ) {
        self.set_forkchoice_updated_response(Self::invalid_status(latest_valid_hash));
    }

    pub fn all_payloads_invalid_block_hash_on_new_payload(&self) {
        self.set_new_payload_response(Self::invalid_block_hash_new_payload_response());
    }

    pub fn all_payloads_invalid_block_hash_on_forkchoice_updated(&self) {
        self.set_forkchoice_updated_response(Self::invalid_block_hash_status());
    }

    pub fn all_payloads_invalid_terminal_block_on_new_payload(&self) {
        self.set_new_payload_response(Self::invalid_terminal_block_new_payload_response());
    }

    pub fn all_payloads_invalid_terminal_block_on_forkchoice_updated(&self) {
        self.set_forkchoice_updated_response(Self::invalid_terminal_block_status());
    }

    /// Disables any static payload responses so the execution block generator will do its own
    /// verification.
    pub fn full_payload_verification(&self) {
        *self.ctx.static_new_payload_response.lock() = None;
        *self.ctx.static_forkchoice_updated_response.lock() = None;
    }

    pub fn insert_pow_block(
        &self,
        block_number: u64,
        block_hash: ExecutionBlockHash,
        parent_hash: ExecutionBlockHash,
        total_difficulty: Uint256,
    ) {
        let block = Block::PoW(PoWBlock {
            block_number,
            block_hash,
            parent_hash,
            total_difficulty,
            timestamp: block_number,
        });

        self.ctx
            .execution_block_generator
            .write()
            // The EF tests supply blocks out of order, so we must import them "without checks" and
            // trust they form valid chains.
            .insert_block_without_checks(block);
    }

    pub fn get_block(&self, block_hash: ExecutionBlockHash) -> Option<Block<E>> {
        self.ctx
            .execution_block_generator
            .read()
            .block_by_hash(block_hash)
    }

    pub fn drop_all_blocks(&self) {
        self.ctx.execution_block_generator.write().drop_all_blocks()
    }

    pub fn set_payload_statuses(&self, block_hash: ExecutionBlockHash, status: PayloadStatusV1) {
        self.set_new_payload_status(block_hash, status.clone());
        self.set_fcu_payload_status(block_hash, status);
    }

    pub fn set_new_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatusV1) {
        self.ctx
            .new_payload_statuses
            .lock()
            .insert(block_hash, Ok(status));
    }

    pub fn set_fcu_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatusV1) {
        self.ctx
            .fcu_payload_statuses
            .lock()
            .insert(block_hash, Ok(status));
    }

    pub fn set_new_payload_error(&self, block_hash: ExecutionBlockHash, error: String) {
        self.ctx
            .new_payload_statuses
            .lock()
            .insert(block_hash, Err(error));
    }

    pub fn set_syncing_response(&self, res: Result<bool, String>) {
        *self.ctx.syncing_response.lock() = res;
    }
}

#[derive(Debug)]
pub enum Error {
    Warp(warp::Error),
    Other(String),
}

impl From<warp::Error> for Error {
    fn from(e: warp::Error) -> Self {
        Error::Warp(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Other(e.to_string())
    }
}

#[derive(Debug)]
struct MissingIdField;

impl warp::reject::Reject for MissingIdField {}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticNewPayloadResponse {
    status: PayloadStatusV1,
    should_import: bool,
}

/// A captured REST-SSZ request (header + path/query + body) recorded by the `/engine/v1/...` routes.
#[derive(Debug, Clone)]
pub struct RestCapture {
    pub method: String,
    pub path: String,
    pub eth_execution_version: Option<String>,
    pub client_version: Option<String>,
    pub content_type: Option<String>,
    pub body: Bytes,
}
#[derive(Debug)]
struct AuthError(String);

impl warp::reject::Reject for AuthError {}

/// A captured `forkchoice_updated` request: the state plus any payload attributes.
pub type CapturedForkchoiceRequest = (ForkchoiceState, Option<PayloadAttributes>);

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<E: EthSpec> {
    pub config: Config,
    pub jwt_key: JwtKey,

    pub last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub last_rest_request: Arc<RwLock<Option<RestCapture>>>,
    pub serve_rest_ssz: bool,
    pub execution_block_generator: RwLock<ExecutionBlockGenerator<E>>,
    pub preloaded_responses: Arc<Mutex<Vec<serde_json::Value>>>,
    pub previous_request: Arc<Mutex<Option<serde_json::Value>>>,
    pub previous_forkchoice_request: Arc<Mutex<Option<CapturedForkchoiceRequest>>>,
    pub static_new_payload_response: Arc<Mutex<Option<StaticNewPayloadResponse>>>,
    pub static_forkchoice_updated_response: Arc<Mutex<Option<PayloadStatusV1>>>,
    pub hook: Arc<Mutex<Hook>>,

    // Canned responses by block hash.
    //
    // This is a more flexible and less stateful alternative to `static_new_payload_response`
    // and `preloaded_responses`.
    pub new_payload_statuses:
        Arc<Mutex<HashMap<ExecutionBlockHash, Result<PayloadStatusV1, String>>>>,
    pub fcu_payload_statuses:
        Arc<Mutex<HashMap<ExecutionBlockHash, Result<PayloadStatusV1, String>>>>,
    pub syncing_response: Arc<Mutex<Result<bool, String>>>,

    pub engine_capabilities: Arc<RwLock<EngineCapabilities>>,
    pub _phantom: PhantomData<E>,
}

impl<E: EthSpec> Context<E> {
    pub fn get_new_payload_status(
        &self,
        block_hash: &ExecutionBlockHash,
    ) -> Option<Result<PayloadStatusV1, String>> {
        self.new_payload_statuses.lock().get(block_hash).cloned()
    }

    pub fn get_fcu_payload_status(
        &self,
        block_hash: &ExecutionBlockHash,
    ) -> Option<Result<PayloadStatusV1, String>> {
        self.fcu_payload_statuses.lock().get(block_hash).cloned()
    }
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: Ipv4Addr::new(127, 0, 0, 1),
            listen_port: 0,
        }
    }
}

/// An API error serializable to JSON.
#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

/// Returns a `warp` header which filters out request that has a missing or incorrectly
/// signed JWT token.
fn auth_header_filter(jwt_key: JwtKey) -> warp::filters::BoxedFilter<()> {
    warp::any()
        .and(warp::filters::header::optional("Authorization"))
        .and_then(move |authorization: Option<String>| {
            let secret = jwt_key.clone();
            async move {
                match authorization {
                    None => Err(warp::reject::custom(AuthError(
                        "auth absent from request".to_string(),
                    ))),
                    Some(auth) => {
                        if let Some(token) = auth.strip_prefix("Bearer ") {
                            match Auth::validate_token(token, &secret) {
                                Ok(_) => Ok(()),
                                Err(e) => Err(warp::reject::custom(AuthError(format!(
                                    "Auth failure: {:?}",
                                    e
                                )))),
                            }
                        } else {
                            Err(warp::reject::custom(AuthError(
                                "Bearer token not present in auth header".to_string(),
                            )))
                        }
                    }
                }
            }
        })
        .untuple_one()
        .boxed()
}
/// This function receives a `Rejection` and tries to return a custom
/// value on invalid auth, otherwise simply passes the rejection along.
async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if let Some(AuthError(e)) = err.find::<AuthError>() {
        message = format!("Authorization error: {}", e);
        code = StatusCode::UNAUTHORIZED;
    } else {
        message = "BAD_REQUEST".to_string();
        code = StatusCode::BAD_REQUEST;
    }

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message,
    });

    Ok(warp::reply::with_status(json, code))
}

const STUB_CAPABILITIES_JSON: &str = r#"{"supported_forks":["paris","shanghai","cancun","prague","osaka","amsterdam"],"fork_scoped_endpoints":["payloads","forkchoice","bodies"],"independently_versioned":{"blobs":["v1","v2","v3","v4"]},"unscoped_endpoints":["capabilities","identity"],"limits":{"bodies.max_count":32,"blobs.max_versioned_hashes":128,"payload.max_bytes":67108864}}"#;

/// Records the REST request into `last_rest_request`, then dispatches to `handle_rest`.
#[allow(clippy::too_many_arguments)]
async fn handle_rest_capture<E: EthSpec>(
    method: &'static str,
    full: warp::path::FullPath,
    query: Option<String>,
    eth_execution_version: Option<String>,
    client_version: Option<String>,
    content_type: Option<String>,
    body: Bytes,
    ctx: Arc<Context<E>>,
) -> Result<warp::http::Response<Bytes>, warp::Rejection> {
    let full_path = full.as_str();

    if !ctx.serve_rest_ssz {
        return Ok(warp::http::Response::builder()
            .status(404)
            .body(Bytes::new())
            .unwrap());
    }

    let path = match &query {
        Some(query) => format!("{full_path}?{query}"),
        None => full_path.to_string(),
    };
    *ctx.last_rest_request.write() = Some(RestCapture {
        method: method.to_string(),
        path,
        eth_execution_version: eth_execution_version.clone(),
        client_version,
        content_type,
        body: body.clone(),
    });

    Ok(handle_rest::handle_rest(
        method,
        full_path,
        query.as_deref(),
        eth_execution_version.as_deref(),
        &body,
        &ctx,
    ))
}

/// Creates a server that will serve requests using information from `ctx`.
///
/// The server will shut down gracefully when the `shutdown` future resolves.
///
/// ## Returns
///
/// This function will bind the server to the provided address and then return a tuple of:
///
/// - `SocketAddr`: the address that the HTTP server will listen on.
/// - `Future`: the actual server future that will need to be awaited.
///
/// ## Errors
///
/// Returns an error if the server is unable to bind or there is another error during
/// configuration.
pub fn serve<E: EthSpec>(
    ctx: Arc<Context<E>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;

    let inner_ctx = ctx.clone();
    let ctx_filter = warp::any().map(move || inner_ctx.clone());

    // `/`
    //
    // Handles actual JSON-RPC requests.
    let root = warp::path::end()
        .and(warp::body::json())
        .and(ctx_filter.clone())
        .and_then(|body: serde_json::Value, ctx: Arc<Context<E>>| async move {
            let id = body
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| warp::reject::custom(MissingIdField))?;
            let preloaded_response = {
                let mut preloaded_responses = ctx.preloaded_responses.lock();
                if !preloaded_responses.is_empty() {
                    Some(preloaded_responses.remove(0))
                } else {
                    None
                }
            };

            let response = if let Some(preloaded_response) = preloaded_response {
                preloaded_response
            } else {
                match handle_rpc(body, ctx).await {
                    Ok(result) => json!({
                        "id": id,
                        "jsonrpc": JSONRPC_VERSION,
                        "result": result
                    }),
                    Err((message, code)) => json!({
                        "id": id,
                        "jsonrpc": JSONRPC_VERSION,
                        "error": {
                            "code": code,
                            "message": message
                        }
                    }),
                }
            };

            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder()
                    .status(200)
                    .body(serde_json::to_string(&response).expect("response must be valid JSON")),
            )
        });

    // `/echo`
    //
    // Sends the body of the request to `ctx.last_echo_request` so we can inspect requests.
    let echo = warp::path("echo")
        .and(warp::body::bytes())
        .and(ctx_filter.clone())
        .and_then(|bytes: Bytes, ctx: Arc<Context<E>>| async move {
            *ctx.last_echo_request.write() = Some(bytes.clone());
            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder().status(200).body(bytes),
            )
        });

    // `/engine/v1/...` REST-SSZ routes.
    let opt_query = || {
        warp::query::raw()
            .map(Some)
            .or(warp::any().map(|| None))
            .unify()
    };
    let rest_post = warp::post()
        .and(warp::path("engine"))
        .and(warp::path("v1"))
        .and(warp::path::full())
        .and(opt_query())
        .and(warp::header::optional::<String>("Eth-Execution-Version"))
        .and(warp::header::optional::<String>("X-Engine-Client-Version"))
        .and(warp::header::optional::<String>("Content-Type"))
        .and(warp::body::bytes())
        .and(ctx_filter.clone())
        .and_then(
            |full, query, eth_version, client_version, content_type, body, ctx| {
                handle_rest_capture(
                    "POST",
                    full,
                    query,
                    eth_version,
                    client_version,
                    content_type,
                    body,
                    ctx,
                )
            },
        );
    let rest_get = warp::get()
        .and(warp::path("engine"))
        .and(warp::path("v1"))
        .and(warp::path::full())
        .and(opt_query())
        .and(warp::header::optional::<String>("Eth-Execution-Version"))
        .and(warp::header::optional::<String>("X-Engine-Client-Version"))
        .and(warp::header::optional::<String>("Content-Type"))
        .and(ctx_filter)
        .and_then(
            |full, query, eth_version, client_version, content_type, ctx| {
                handle_rest_capture(
                    "GET",
                    full,
                    query,
                    eth_version,
                    client_version,
                    content_type,
                    Bytes::new(),
                    ctx,
                )
            },
        );

    let routes = auth_header_filter(ctx.jwt_key.clone())
        .and(warp::post().and(root.or(echo)).or(rest_post).or(rest_get))
        .recover(handle_rejection)
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-mock-execution-client"));

    let std_listener =
        std::net::TcpListener::bind(SocketAddrV4::new(config.listen_addr, config.listen_port))?;
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let listening_socket = listener.local_addr()?;

    let server = warp::serve(routes)
        .incoming(listener)
        .graceful(async {
            shutdown.await;
        })
        .run();

    info!(
        listen_address = listening_socket.to_string(),
        "Mock execution client started"
    );

    Ok((listening_socket, server))
}
