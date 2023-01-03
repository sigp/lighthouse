//! Provides a mock execution engine HTTP JSON-RPC API for use in testing.

use crate::engine_api::auth::JwtKey;
use crate::engine_api::{
    auth::Auth, http::JSONRPC_VERSION, ExecutionBlock, PayloadStatusV1, PayloadStatusV1Status,
};
use bytes::Bytes;
use environment::null_logger;
use execution_block_generator::PoWBlock;
use handle_rpc::handle_rpc;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use serde::{Deserialize, Serialize};
use serde_json::json;
use slog::{info, Logger};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::{runtime, sync::oneshot};
use types::{EthSpec, ExecutionBlockHash, Uint256};
use warp::{http::StatusCode, Filter, Rejection};

pub use execution_block_generator::{generate_pow_block, Block, ExecutionBlockGenerator};
pub use hook::Hook;
pub use mock_builder::{Context as MockBuilderContext, MockBuilder, Operation, TestingBuilder};
pub use mock_execution_layer::MockExecutionLayer;

pub const DEFAULT_TERMINAL_DIFFICULTY: u64 = 6400;
pub const DEFAULT_TERMINAL_BLOCK: u64 = 64;
pub const DEFAULT_JWT_SECRET: [u8; 32] = [42; 32];
pub const DEFAULT_BUILDER_THRESHOLD_WEI: u128 = 1_000_000_000_000_000_000;

mod execution_block_generator;
mod handle_rpc;
mod hook;
mod mock_builder;
mod mock_execution_layer;

/// Configuration for the MockExecutionLayer.
pub struct MockExecutionConfig {
    pub server_config: Config,
    pub jwt_key: JwtKey,
    pub terminal_difficulty: Uint256,
    pub terminal_block: u64,
    pub terminal_block_hash: ExecutionBlockHash,
    pub shanghai_time: Option<u64>,
    pub eip4844_time: Option<u64>,
}

impl Default for MockExecutionConfig {
    fn default() -> Self {
        Self {
            jwt_key: JwtKey::random(),
            terminal_difficulty: DEFAULT_TERMINAL_DIFFICULTY.into(),
            terminal_block: DEFAULT_TERMINAL_BLOCK,
            terminal_block_hash: ExecutionBlockHash::zero(),
            server_config: Config::default(),
            shanghai_time: None,
            eip4844_time: None,
        }
    }
}

pub struct MockServer<T: EthSpec> {
    _shutdown_tx: oneshot::Sender<()>,
    listen_socket_addr: SocketAddr,
    last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub ctx: Arc<Context<T>>,
}

impl<T: EthSpec> MockServer<T> {
    pub fn unit_testing() -> Self {
        Self::new(
            &runtime::Handle::current(),
            JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(),
            DEFAULT_TERMINAL_DIFFICULTY.into(),
            DEFAULT_TERMINAL_BLOCK,
            ExecutionBlockHash::zero(),
            None, // FIXME(capella): should this be the default?
            None, // FIXME(eip4844): should this be the default?
        )
    }

    pub fn new_with_config(handle: &runtime::Handle, config: MockExecutionConfig) -> Self {
        let MockExecutionConfig {
            jwt_key,
            terminal_difficulty,
            terminal_block,
            terminal_block_hash,
            server_config,
            shanghai_time,
            eip4844_time,
        } = config;
        let last_echo_request = Arc::new(RwLock::new(None));
        let preloaded_responses = Arc::new(Mutex::new(vec![]));
        let execution_block_generator = ExecutionBlockGenerator::new(
            terminal_difficulty,
            terminal_block,
            terminal_block_hash,
            shanghai_time,
            eip4844_time,
        );

        let ctx: Arc<Context<T>> = Arc::new(Context {
            config: server_config,
            jwt_key,
            log: null_logger().unwrap(),
            last_echo_request: last_echo_request.clone(),
            execution_block_generator: RwLock::new(execution_block_generator),
            previous_request: <_>::default(),
            preloaded_responses,
            static_new_payload_response: <_>::default(),
            static_forkchoice_updated_response: <_>::default(),
            static_get_block_by_hash_response: <_>::default(),
            hook: <_>::default(),
            new_payload_statuses: <_>::default(),
            fcu_payload_statuses: <_>::default(),
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

    pub fn new(
        handle: &runtime::Handle,
        jwt_key: JwtKey,
        terminal_difficulty: Uint256,
        terminal_block: u64,
        terminal_block_hash: ExecutionBlockHash,
        shanghai_time: Option<u64>,
        eip4844_time: Option<u64>,
    ) -> Self {
        Self::new_with_config(
            handle,
            MockExecutionConfig {
                server_config: Config::default(),
                jwt_key,
                terminal_difficulty,
                terminal_block,
                terminal_block_hash,
                shanghai_time,
                eip4844_time,
            },
        )
    }

    pub fn execution_block_generator(&self) -> RwLockWriteGuard<'_, ExecutionBlockGenerator<T>> {
        self.ctx.execution_block_generator.write()
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

    pub fn push_preloaded_response(&self, response: serde_json::Value) {
        self.ctx.preloaded_responses.lock().push(response)
    }

    pub fn take_previous_request(&self) -> Option<serde_json::Value> {
        self.ctx.previous_request.lock().take()
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

    /// This will make the node appear like it is syncing.
    pub fn all_get_block_by_hash_requests_return_none(&self) {
        *self.ctx.static_get_block_by_hash_response.lock() = Some(None);
    }

    /// The node will respond "naturally"; it will return blocks if they're known to it.
    pub fn all_get_block_by_hash_requests_return_natural_value(&self) {
        *self.ctx.static_get_block_by_hash_response.lock() = None;
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

    pub fn get_block(&self, block_hash: ExecutionBlockHash) -> Option<Block<T>> {
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
            .insert(block_hash, status);
    }

    pub fn set_fcu_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatusV1) {
        self.ctx
            .fcu_payload_statuses
            .lock()
            .insert(block_hash, status);
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

#[derive(Debug)]
struct MissingIdField;

impl warp::reject::Reject for MissingIdField {}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticNewPayloadResponse {
    status: PayloadStatusV1,
    should_import: bool,
}
#[derive(Debug)]
struct AuthError(String);

impl warp::reject::Reject for AuthError {}

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T: EthSpec> {
    pub config: Config,
    pub jwt_key: JwtKey,
    pub log: Logger,
    pub last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub execution_block_generator: RwLock<ExecutionBlockGenerator<T>>,
    pub preloaded_responses: Arc<Mutex<Vec<serde_json::Value>>>,
    pub previous_request: Arc<Mutex<Option<serde_json::Value>>>,
    pub static_new_payload_response: Arc<Mutex<Option<StaticNewPayloadResponse>>>,
    pub static_forkchoice_updated_response: Arc<Mutex<Option<PayloadStatusV1>>>,
    pub static_get_block_by_hash_response: Arc<Mutex<Option<Option<ExecutionBlock>>>>,
    pub hook: Arc<Mutex<Hook>>,

    // Canned responses by block hash.
    //
    // This is a more flexible and less stateful alternative to `static_new_payload_response`
    // and `preloaded_responses`.
    pub new_payload_statuses: Arc<Mutex<HashMap<ExecutionBlockHash, PayloadStatusV1>>>,
    pub fcu_payload_statuses: Arc<Mutex<HashMap<ExecutionBlockHash, PayloadStatusV1>>>,

    pub _phantom: PhantomData<T>,
}

impl<T: EthSpec> Context<T> {
    pub fn get_new_payload_status(
        &self,
        block_hash: &ExecutionBlockHash,
    ) -> Option<PayloadStatusV1> {
        self.new_payload_statuses.lock().get(block_hash).cloned()
    }

    pub fn get_fcu_payload_status(
        &self,
        block_hash: &ExecutionBlockHash,
    ) -> Option<PayloadStatusV1> {
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

    if let Some(e) = err.find::<AuthError>() {
        message = format!("Authorization error: {:?}", e);
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
pub fn serve<T: EthSpec>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;
    let log = ctx.log.clone();

    let inner_ctx = ctx.clone();
    let ctx_filter = warp::any().map(move || inner_ctx.clone());

    // `/`
    //
    // Handles actual JSON-RPC requests.
    let root = warp::path::end()
        .and(warp::body::json())
        .and(ctx_filter.clone())
        .and_then(|body: serde_json::Value, ctx: Arc<Context<T>>| async move {
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
                    Err(message) => json!({
                        "id": id,
                        "jsonrpc": JSONRPC_VERSION,
                        "error": {
                            "code": -1234,   // Junk error code.
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
        .and(ctx_filter)
        .and_then(|bytes: Bytes, ctx: Arc<Context<T>>| async move {
            *ctx.last_echo_request.write() = Some(bytes.clone());
            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder().status(200).body(bytes),
            )
        });

    let routes = warp::post()
        .and(auth_header_filter(ctx.jwt_key.clone()))
        .and(root.or(echo))
        .recover(handle_rejection)
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-mock-execution-client"));

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddrV4::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!(
        log,
        "Metrics HTTP server started";
        "listen_address" => listening_socket.to_string(),
    );

    Ok((listening_socket, server))
}
