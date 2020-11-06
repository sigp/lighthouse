use crate::api_error::ApiError;
use crate::backend::{get_keys, sign_message};
use crate::handler::Handler;
use crate::rest_api::Context;
use crate::upcheck::upcheck;
use client_backend::Storage;
use hyper::{Body, Method, Request, Response};
use slog::debug;
use std::sync::Arc;
use std::time::Instant;
use types::EthSpec;

pub async fn on_http_request<E: EthSpec, S: Storage>(
    req: Request<Body>,
    ctx: Arc<Context<E, S>>,
) -> Result<Response<Body>, ApiError> {
    let path = req.uri().path().to_string();
    let received_instant = Instant::now();
    let log = ctx.log.clone();

    match route(req, ctx).await {
        Ok(response) => {
            debug!(
                log,
                "HTTP API request successful";
                "path" => path,
                "duration_ms" => Instant::now().duration_since(received_instant).as_millis()
            );
            Ok(response)
        }

        Err(error) => {
            debug!(
                log,
                "HTTP API request failure";
                "path" => path,
                "duration_ms" => Instant::now().duration_since(received_instant).as_millis()
            );
            Ok(error.into())
        }
    }
}

async fn route<E: EthSpec, S: Storage>(
    req: Request<Body>,
    ctx: Arc<Context<E, S>>,
) -> Result<Response<Body>, ApiError> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let ctx = ctx.clone();
    let handler = Handler::new(req, ctx)?;

    match (method, path.as_ref()) {
        (Method::GET, "/upcheck") => handler.static_value(upcheck()).await?.serde_encodings(),

        (Method::GET, "/keys") => handler.in_blocking_task(get_keys).await?.serde_encodings(),

        (Method::POST, _) => route_post(&path, handler).await,

        _ => Err(ApiError::NotFound(
            "Request path and/or method not found.".to_string(),
        )),
    }
}

/// Responds to all the POST requests.
///
/// Should be deprecated once a better routing library is used, such as `warp`
async fn route_post<E: EthSpec, S: Storage>(
    path: &str,
    handler: Handler<E, S>,
) -> Result<Response<Body>, ApiError> {
    let mut path_segments = path[1..].trim_end_matches('/').split('/');

    match path_segments.next() {
        Some("sign") => {
            let path_segments_count = path_segments.clone().count();

            if path_segments_count == 0 {
                return Err(ApiError::BadRequest(
                    "Parameter public_key needed in route /sign/:public_key".to_string(),
                ));
            }

            if path_segments_count > 1 {
                return Err(ApiError::BadRequest(
                    "Only one path segment is allowed after /sign".to_string(),
                ));
            }

            handler
                .allow_body()
                .in_blocking_task(sign_message)
                .await?
                .serde_encodings()
        }
        _ => Err(ApiError::NotFound(
            "Request path and/or method not found.".to_string(),
        )),
    }
}
