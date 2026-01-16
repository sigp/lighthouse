use crate::config::MetricsConfig;
use lighthouse_version::version_with_platform;
use logging::crit;
use std::future::Future;
use std::net::SocketAddr;
use tracing::info;
use warp::{Filter, http::Response};

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

/// Creates a server that will serve Prometheus metrics.
pub fn serve(
    config: MetricsConfig,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
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

    if !config.enabled {
        crit!("Cannot start disabled metrics HTTP server");
        return Err(Error::Other(
            "A disabled metrics server should not be started".to_string(),
        ));
    }

    let routes = warp::get()
        .and(warp::path("metrics"))
        .and_then(|| async move {
            let mut buffer = String::new();
            let encoder = metrics::TextEncoder::new();

            // Scrape health metrics (CPU, Memory, etc.)
            health_metrics::metrics::scrape_health_metrics();

            // metrics::gather() returns Vec<MetricFamily>, which is what we want to encode.

            match encoder.encode_utf8(&metrics::gather(), &mut buffer) {
                Ok(()) => Ok::<_, warp::Rejection>(
                    Response::builder()
                        .status(200)
                        .header("Content-Type", "text/plain")
                        .body(buffer)
                        .unwrap()
                ),
                Err(e) => Ok::<_, warp::Rejection>(
                    Response::builder()
                        .status(500)
                        .header("Content-Type", "text/plain")
                        .body(format!("Unable to gather metrics: {:?}", e))
                        .unwrap()
                ),
            }
        })
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddr::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!(
        listen_address = listening_socket.to_string(),
        "Metrics HTTP server started"
    );

    Ok((listening_socket, server))
}
