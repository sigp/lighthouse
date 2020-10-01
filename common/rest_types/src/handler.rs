use crate::{ApiError, ApiResult};
use hyper::header;
use hyper::{Body, Request, Response, StatusCode};
use serde::Deserialize;
use serde::Serialize;
use ssz::Encode;
use task_executor::TaskExecutor;

/// Defines the encoding for the API.
#[derive(Clone, Serialize, Deserialize, Copy)]
pub enum ApiEncodingFormat {
    JSON,
    YAML,
    SSZ,
}

impl ApiEncodingFormat {
    pub fn get_content_type(&self) -> &str {
        match self {
            ApiEncodingFormat::JSON => "application/json",
            ApiEncodingFormat::YAML => "application/yaml",
            ApiEncodingFormat::SSZ => "application/ssz",
        }
    }
}

impl From<&str> for ApiEncodingFormat {
    fn from(f: &str) -> ApiEncodingFormat {
        match f {
            "application/yaml" => ApiEncodingFormat::YAML,
            "application/ssz" => ApiEncodingFormat::SSZ,
            _ => ApiEncodingFormat::JSON,
        }
    }
}

/// Provides a HTTP request handler with Lighthouse-specific functionality.
pub struct Handler<T> {
    executor: TaskExecutor,
    req: Request<()>,
    body: Body,
    ctx: T,
    encoding: ApiEncodingFormat,
    allow_body: bool,
}

impl<T: Clone + Send + Sync + 'static> Handler<T> {
    /// Start handling a new request.
    pub fn new(req: Request<Body>, ctx: T, executor: TaskExecutor) -> Result<Self, ApiError> {
        let (req_parts, body) = req.into_parts();
        let req = Request::from_parts(req_parts, ());

        let accept_header: String = req
            .headers()
            .get(header::ACCEPT)
            .map_or(Ok(""), |h| h.to_str())
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "The Accept header contains invalid characters: {:?}",
                    e
                ))
            })
            .map(String::from)?;

        Ok(Self {
            executor,
            req,
            body,
            ctx,
            allow_body: false,
            encoding: ApiEncodingFormat::from(accept_header.as_str()),
        })
    }

    /// The default behaviour is to return an error if any body is supplied in the request. Calling
    /// this function disables that error.
    pub fn allow_body(mut self) -> Self {
        self.allow_body = true;
        self
    }

    /// Return a simple static value.
    ///
    /// Does not use the blocking executor.
    pub async fn static_value<V>(self, value: V) -> Result<HandledRequest<V>, ApiError> {
        // Always check and disallow a body for a static value.
        let _ = Self::get_body(self.body, false).await?;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    /// Calls `func` in-line, on the core executor.
    ///
    /// This should only be used for very fast tasks.
    pub async fn in_core_task<F, V>(self, func: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Request<Vec<u8>>, T) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let body = Self::get_body(self.body, self.allow_body).await?;
        let (req_parts, _) = self.req.into_parts();
        let req = Request::from_parts(req_parts, body);

        let value = func(req, self.ctx)?;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    /// Spawns `func` on the blocking executor.
    ///
    /// This method is suitable for handling long-running or intensive tasks.
    pub async fn in_blocking_task<F, V>(self, func: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Request<Vec<u8>>, T) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let ctx = self.ctx;
        let body = Self::get_body(self.body, self.allow_body).await?;
        let (req_parts, _) = self.req.into_parts();
        let req = Request::from_parts(req_parts, body);

        let value = self
            .executor
            .clone()
            .runtime_handle()
            .spawn_blocking(move || func(req, ctx))
            .await
            .map_err(|e| {
                ApiError::ServerError(format!(
                    "Failed to get blocking join handle: {}",
                    e.to_string()
                ))
            })??;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    /// Call `func`, then return a response that is suitable for an SSE stream.
    pub async fn sse_stream<F>(self, func: F) -> ApiResult
    where
        F: Fn(Request<()>, T) -> Result<Body, ApiError>,
    {
        let body = func(self.req, self.ctx)?;

        Response::builder()
            .status(200)
            .header("Content-Type", "text/event-stream")
            .header("Connection", "Keep-Alive")
            .header("Cache-Control", "no-cache")
            .header("Access-Control-Allow-Origin", "*")
            .body(body)
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
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

/// A request that has been "handled" and now a result (`value`) needs to be serialize and
/// returned.
pub struct HandledRequest<V> {
    encoding: ApiEncodingFormat,
    value: V,
}

impl HandledRequest<String> {
    /// Simple encode a string as utf-8.
    pub fn text_encoding(self) -> ApiResult {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(self.value))
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}

impl<V: Serialize + Encode> HandledRequest<V> {
    /// Suitable for all items which implement `serde` and `ssz`.
    pub fn all_encodings(self) -> ApiResult {
        match self.encoding {
            ApiEncodingFormat::SSZ => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/ssz")
                .body(Body::from(self.value.as_ssz_bytes()))
                .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e))),
            _ => self.serde_encodings(),
        }
    }
}

impl<V: Serialize> HandledRequest<V> {
    /// Suitable for items which only implement `serde`.
    pub fn serde_encodings(self) -> ApiResult {
        let (body, content_type) = match self.encoding {
            ApiEncodingFormat::JSON => (
                Body::from(serde_json::to_string(&self.value).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as JSON: {:?}",
                        e
                    ))
                })?),
                "application/json",
            ),
            ApiEncodingFormat::SSZ => {
                return Err(ApiError::UnsupportedType(
                    "Response cannot be encoded as SSZ.".into(),
                ));
            }
            ApiEncodingFormat::YAML => (
                Body::from(serde_yaml::to_string(&self.value).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as YAML: {:?}",
                        e
                    ))
                })?),
                "application/yaml",
            ),
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(body)
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}
