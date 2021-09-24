use bytes::Bytes;
use environment::null_logger;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use types::EthSpec;
use warp::Filter;

pub struct MockServer {
    _shutdown_tx: oneshot::Sender<()>,
    listen_socket_addr: SocketAddr,
    last_echo_request: Arc<RwLock<Option<Bytes>>>,
}

impl MockServer {
    pub fn unit_testing<T: EthSpec>() -> Self {
        let last_echo_request = Arc::new(RwLock::new(None));

        let ctx: Arc<Context<T>> = Arc::new(Context {
            config: <_>::default(),
            log: null_logger().unwrap(),
            last_echo_request: last_echo_request.clone(),
            _phantom: PhantomData,
        });

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let shutdown_future = async {
            // Ignore the result from the channel, shut down regardless.
            let _ = shutdown_rx.await;
        };

        let (listen_socket_addr, server_future) = serve(ctx, shutdown_future).unwrap();

        tokio::spawn(server_future);

        Self {
            _shutdown_tx: shutdown_tx,
            listen_socket_addr,
            last_echo_request,
        }
    }

    pub fn url(&self) -> String {
        format!(
            "http://{}:{}",
            self.listen_socket_addr.ip(),
            self.listen_socket_addr.port()
        )
    }

    pub async fn last_echo_request(&self) -> Bytes {
        self.last_echo_request
            .write()
            .await
            .take()
            .expect("last echo request is none")
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

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T> {
    pub config: Config,
    pub log: Logger,
    pub last_echo_request: Arc<RwLock<Option<Bytes>>>,
    pub _phantom: PhantomData<T>,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: Ipv4Addr::new(127, 0, 0, 1),
            listen_port: 0,
            allow_origin: None,
        }
    }
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

    // Configure CORS.
    let cors_builder = {
        let builder = warp::cors()
            .allow_method("GET")
            .allow_headers(vec!["Content-Type"]);

        warp_utils::cors::set_builder_origins(
            builder,
            config.allow_origin.as_deref(),
            (config.listen_addr, config.listen_port),
        )?
    };

    let inner_ctx = ctx.clone();
    let routes = warp::post()
        .and(warp::path("echo"))
        .and(warp::body::bytes())
        .and(warp::any().map(move || inner_ctx.clone()))
        .and_then(|bytes: Bytes, ctx: Arc<Context<T>>| async move {
            *ctx.last_echo_request.write().await = Some(bytes.clone());
            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder().status(200).body(bytes),
            )
        })
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-mock-execution-client"))
        .with(cors_builder.build());

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
