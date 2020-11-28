use crate::api_error::{ApiError, ApiResult};
use crate::rest_api::Context;
use hyper::{Body, Request, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use types::EthSpec;

/// Provides a HTTP request handler with specific functionality.
pub struct Handler<E: EthSpec, S: Send + Sync> {
    req: Request<()>,
    body: Body,
    ctx: Arc<Context<E, S>>,
    allow_body: bool,
}

impl<E: EthSpec, S: 'static + Send + Sync> Handler<E, S> {
    /// Start handling a new request.
    pub fn new(req: Request<Body>, ctx: Arc<Context<E, S>>) -> Result<Self, ApiError> {
        let (req_parts, body) = req.into_parts();
        let req = Request::from_parts(req_parts, ());

        Ok(Self {
            req,
            body,
            ctx,
            allow_body: false,
        })
    }

    /// Return a simple static value.
    ///
    /// Does not use the blocking executor.
    pub async fn static_value<V>(self, value: V) -> Result<HandledRequest<V>, ApiError> {
        // Always check and disallow a body for a static value.
        let _ = Self::get_body(self.body, false).await?;

        Ok(HandledRequest { value })
    }

    /// The default behaviour is to return an error if any body is supplied in the request. Calling
    /// this function disables that error.
    pub fn allow_body(mut self) -> Self {
        self.allow_body = true;
        self
    }

    /// Spawns `func` on the blocking executor.
    ///
    /// This method is suitable for handling long-running or intensive tasks.
    pub async fn in_blocking_task<F, V>(self, func: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Request<Vec<u8>>, Arc<Context<E, S>>) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let ctx = self.ctx;
        let executor = ctx.executor.clone();
        let body = Self::get_body(self.body, self.allow_body).await?;
        let (req_parts, _) = self.req.into_parts();
        let req = Request::from_parts(req_parts, body);

        // NOTE: The task executor now holds a weak reference to the global runtime. On shutdown
        // there may be no runtime available.
        // All these edge cases must be handled here.
        let value = executor
            .spawn_blocking_handle(move || func(req, ctx), "remote_signer_request")
            .ok_or_else(|| ApiError::ServerError("Runtime does not exist".to_string()))?
            .await
            .map_err(|_| ApiError::ServerError("Panic during execution".to_string()))??;

        Ok(HandledRequest { value })
    }

    /// Downloads the bytes for `body`.
    async fn get_body(body: Body, allow_body: bool) -> Result<Vec<u8>, ApiError> {
        let bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))?;

        if !allow_body && !bytes[..].is_empty() {
            Err(ApiError::BadRequest(
                "The request body must be empty".to_string(),
            ))
        } else {
            Ok(bytes.into_iter().collect())
        }
    }
}

/// A request that has been "handled" and now a result (`value`) needs to be serialized and
/// returned.
pub struct HandledRequest<V> {
    value: V,
}

impl<V: Serialize> HandledRequest<V> {
    /// Suitable for items which only implement `serde`.
    pub fn serde_encodings(self) -> ApiResult {
        let body = Body::from(serde_json::to_string(&self.value).map_err(|e| {
            ApiError::ServerError(format!(
                "Unable to serialize response body as JSON: {:?}",
                e
            ))
        })?);

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(body)
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}
