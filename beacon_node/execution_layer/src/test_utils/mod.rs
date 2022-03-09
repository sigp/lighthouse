//! Provides a mock execution engine HTTP JSON-RPC API for use in testing.

use crate::engine_api::auth::JwtKey;
use crate::engine_api::{
    auth::Auth, http::JSONRPC_VERSION, PayloadStatusV1, PayloadStatusV1Status,
};
use bytes::Bytes;
use environment::null_logger;
use execution_block_generator::{Block, PoWBlock};
use handle_rpc::handle_rpc;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use serde::{Deserialize, Serialize};
use serde_json::json;
use slog::{info, Logger};
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::{runtime, sync::oneshot};
use types::{EthSpec, ExecutionBlockHash, Uint256};
use warp::{http::StatusCode, Filter, Rejection};

pub use execution_block_generator::{generate_pow_block, ExecutionBlockGenerator};
pub use mock_execution_layer::{ExecutionLayerRuntime, MockExecutionLayer};

pub const DEFAULT_TERMINAL_DIFFICULTY: u64 = 6400;
pub const DEFAULT_TERMINAL_BLOCK: u64 = 64;
pub const JWT_SECRET: [u8; 32] = [42; 32];

mod execution_block_generator;
mod handle_rpc;
mod mock_execution_layer;

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
            DEFAULT_TERMINAL_DIFFICULTY.into(),
            DEFAULT_TERMINAL_BLOCK,
            ExecutionBlockHash::zero(),
        )
    }

    pub fn new(
        handle: &runtime::Handle,
        terminal_difficulty: Uint256,
        terminal_block: u64,
        terminal_block_hash: ExecutionBlockHash,
    ) -> Self {
        let last_echo_request = Arc::new(RwLock::new(None));
        let preloaded_responses = Arc::new(Mutex::new(vec![]));
        let execution_block_generator =
            ExecutionBlockGenerator::new(terminal_difficulty, terminal_block, terminal_block_hash);

        let ctx: Arc<Context<T>> = Arc::new(Context {
            config: <_>::default(),
            log: null_logger().unwrap(),
            last_echo_request: last_echo_request.clone(),
            execution_block_generator: RwLock::new(execution_block_generator),
            previous_request: <_>::default(),
            preloaded_responses,
            static_new_payload_response: <_>::default(),
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

    pub fn all_payloads_valid(&self) {
        let response = StaticNewPayloadResponse {
            status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Valid,
                latest_valid_hash: None,
                validation_error: None,
            },
            should_import: true,
        };
        *self.ctx.static_new_payload_response.lock() = Some(response)
    }

    /// Setting `should_import = true` simulates an EE that initially returns `SYNCING` but obtains
    /// the block via it's own means (e.g., devp2p).
    pub fn all_payloads_syncing(&self, should_import: bool) {
        let response = StaticNewPayloadResponse {
            status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Syncing,
                latest_valid_hash: None,
                validation_error: None,
            },
            should_import,
        };
        *self.ctx.static_new_payload_response.lock() = Some(response)
    }

    pub fn all_payloads_invalid(&self, latest_valid_hash: ExecutionBlockHash) {
        let response = StaticNewPayloadResponse {
            status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Invalid,
                latest_valid_hash: Some(latest_valid_hash),
                validation_error: Some("static response".into()),
            },
            should_import: true,
        };
        *self.ctx.static_new_payload_response.lock() = Some(response)
    }

    /// Disables any static payload response so the execution block generator will do its own
    /// verification.
    pub fn full_payload_verification(&self) {
        *self.ctx.static_new_payload_response.lock() = None
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
        });

        self.ctx
            .execution_block_generator
            .write()
            // The EF tests supply blocks out of order, so we must import them "without checks" and
            // trust they form valid chains.
            .insert_block_without_checks(block)
            .unwrap()
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
    pub log: Logger,
    pub last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub execution_block_generator: RwLock<ExecutionBlockGenerator<T>>,
    pub preloaded_responses: Arc<Mutex<Vec<serde_json::Value>>>,
    pub previous_request: Arc<Mutex<Option<serde_json::Value>>>,
    pub static_new_payload_response: Arc<Mutex<Option<StaticNewPayloadResponse>>>,
    pub _phantom: PhantomData<T>,
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
fn auth_header_filter() -> warp::filters::BoxedFilter<()> {
    warp::any()
        .and(warp::filters::header::optional("Authorization"))
        .and_then(move |authorization: Option<String>| async move {
            match authorization {
                None => Err(warp::reject::custom(AuthError(
                    "auth absent from request".to_string(),
                ))),
                Some(auth) => {
                    if let Some(token) = auth.strip_prefix("Bearer ") {
                        let secret = JwtKey::from_slice(&JWT_SECRET).unwrap();
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
        .and(auth_header_filter())
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
