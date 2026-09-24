//! Bounded JSON reads from untrusted light-client REST providers.
//!
//! This is additive to [`BeaconNodeHttpClient`]: existing callers retain their timeout, redirect
//! and error-body behaviour. These reads do not authenticate data or decide whether to retry.
//! The returned version is decoding context, not proof of the header's fork or finality.

mod error;
#[cfg(test)]
mod tests;
pub use error::{RequestError, RequestErrorKind};

use crate::{BeaconNodeHttpClient, ForkVersionedResponse, SensitiveUrl, Timeouts};
use reqwest::{StatusCode, Url, header};
use serde::de::DeserializeOwned;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::Semaphore, time::Instant};
use types::{
    EthSpec, Hash256, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate,
    light_client::consts::MAX_REQUEST_LIGHT_CLIENT_UPDATES,
};

/// A single request's deadline (including queueing and decoding) and maximum body size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    timeout: Duration,
    max_response_bytes: u64,
}

impl RequestLimits {
    pub fn new(timeout: Duration, max_response_bytes: u64) -> Result<Self, RequestError> {
        if timeout.is_zero()
            || max_response_bytes == 0
            || usize::try_from(max_response_bytes).is_err()
            || std::time::Instant::now().checked_add(timeout).is_none()
        {
            return Err(RequestError::new(RequestErrorKind::InvalidLimits));
        }
        Ok(Self {
            timeout,
            max_response_bytes,
        })
    }

    pub fn timeout(self) -> Duration {
        self.timeout
    }
    pub fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
}

/// Unauthenticated, fork-aware JSON data and locally measured response-body bytes.
#[derive(Debug)]
pub struct BoundedResponse<T> {
    pub data: T,
    pub bytes_received: u64,
}

/// A reusable client for the three JSON light-client endpoints, with no automatic redirects.
///
/// Use on the caller's Tokio runtime with its I/O and time drivers enabled. Clones share a
/// single request/decoder permit: cancellation cannot build an unbounded queue of detached
/// blocking decoders. An already running decoder may finish, but only owns untrusted data.
/// Compression is disabled even under Cargo feature unification; encoded responses are rejected
/// so body accounting always measures bytes delivered to the JSON decoder.
#[derive(Clone, Debug)]
pub struct LightClientHttpClient {
    inner: BeaconNodeHttpClient,
    permit: Arc<Semaphore>,
}

impl LightClientHttpClient {
    pub fn new(server: SensitiveUrl) -> Result<Self, RequestError> {
        if !matches!(server.expose_full().scheme(), "http" | "https")
            || server.expose_full().cannot_be_a_base()
        {
            return Err(RequestError::new(RequestErrorKind::InvalidUrl));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()
            .map_err(|error| RequestError::new(http_error(error)))?;
        Ok(Self {
            // All bounded reads set their own explicit timeout; no existing caller is changed.
            inner: BeaconNodeHttpClient::from_components(
                server,
                client,
                Timeouts::set_all(Duration::ZERO),
            ),
            permit: Arc::new(Semaphore::new(1)),
        })
    }

    pub async fn get_bootstrap<E: EthSpec>(
        &self,
        block_root: Hash256,
        limits: RequestLimits,
    ) -> Result<BoundedResponse<ForkVersionedResponse<LightClientBootstrap<E>>>, RequestError> {
        let path = self
            .inner
            .light_client_bootstrap_path(block_root)
            .map_err(|_| RequestError::new(RequestErrorKind::InvalidUrl))?;
        self.get_json(path, limits).await
    }

    /// The response is a top-level array of versioned updates, not an outer data envelope.
    /// Empty/short pages are preserved; committee continuity belongs to the consumer verifier.
    pub async fn get_updates<E: EthSpec>(
        &self,
        start_period: u64,
        count: u64,
        limits: RequestLimits,
    ) -> Result<BoundedResponse<Vec<ForkVersionedResponse<LightClientUpdate<E>>>>, RequestError>
    {
        if count == 0
            || count > MAX_REQUEST_LIGHT_CLIENT_UPDATES
            || start_period.checked_add(count).is_none()
        {
            return Err(RequestError::new(RequestErrorKind::InvalidRange));
        }
        let path = self
            .inner
            .light_client_updates_path(start_period, count)
            .map_err(|_| RequestError::new(RequestErrorKind::InvalidUrl))?;
        self.get_json(path, limits).await
    }

    pub async fn get_finality_update<E: EthSpec>(
        &self,
        limits: RequestLimits,
    ) -> Result<BoundedResponse<ForkVersionedResponse<LightClientFinalityUpdate<E>>>, RequestError>
    {
        let path = self
            .inner
            .light_client_path("finality_update")
            .map_err(|_| RequestError::new(RequestErrorKind::InvalidUrl))?;
        self.get_json(path, limits).await
    }

    async fn get_json<T: DeserializeOwned + Send + 'static>(
        &self,
        path: Url,
        limits: RequestLimits,
    ) -> Result<BoundedResponse<T>, RequestError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| RequestError::new(RequestErrorKind::RuntimeUnavailable))?;
        let deadline = Instant::now()
            .checked_add(limits.timeout)
            .ok_or_else(|| RequestError::new(RequestErrorKind::InvalidLimits))?;
        let mut status = None;
        let mut retry_after = None;
        let mut bytes_received = 0u64;
        let request = async {
            let permit = self
                .permit
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| RequestErrorKind::RuntimeUnavailable)?;
            // A ready permit can be polled before timeout_at notices its elapsed timer.
            if Instant::now() >= deadline {
                return Err(RequestErrorKind::Timeout);
            }
            let mut response = self
                .inner
                .client
                .get(path)
                .header(header::ACCEPT, crate::JSON_CONTENT_TYPE_HEADER)
                .header(header::ACCEPT_ENCODING, "identity")
                .timeout(limits.timeout)
                .send()
                .await
                .map_err(http_error)?;
            let response_status = response.status();
            status = Some(response_status);
            retry_after = parse_retry_after(response.headers())?;
            if response_status == StatusCode::OK {
                let mut content_types = response.headers().get_all(header::CONTENT_TYPE).iter();
                let is_json = content_types
                    .next()
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| mediatype::MediaType::parse(value).ok())
                    .is_some_and(|value| {
                        value.ty == mediatype::names::APPLICATION
                            && value.subty == mediatype::names::JSON
                            && value.suffix.is_none()
                    });
                if !is_json || content_types.next().is_some() {
                    return Err(RequestErrorKind::InvalidHeaders);
                }
            }
            // Never silently parse compressed bytes or let feature unification change the budget.
            for encoding in response.headers().get_all(header::CONTENT_ENCODING) {
                if !encoding
                    .to_str()
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
                {
                    return Err(RequestErrorKind::InvalidHeaders);
                }
            }
            let too_large = || RequestErrorKind::BodyTooLarge {
                limit: limits.max_response_bytes,
            };
            if response
                .content_length()
                .is_some_and(|length| length > limits.max_response_bytes)
            {
                // Advertised size is only an early rejection hint, never measured usage.
                return Err(too_large());
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(http_error)? {
                let length = u64::try_from(chunk.len()).map_err(|_| too_large())?;
                bytes_received = bytes_received.checked_add(length).ok_or_else(too_large)?;
                if bytes_received > limits.max_response_bytes {
                    return Err(too_large());
                }
                // Error bodies are counted and bounded but never parsed, retained or logged.
                if response_status == StatusCode::OK {
                    body.try_reserve(chunk.len())
                        .map_err(|_| RequestErrorKind::AllocationFailed)?;
                    body.extend_from_slice(&chunk);
                }
            }
            if response_status != StatusCode::OK {
                return Err(RequestErrorKind::Status);
            }
            // Do not queue work once the deadline has elapsed even if the body future was Ready.
            if Instant::now() >= deadline {
                return Err(RequestErrorKind::Timeout);
            }
            runtime
                .spawn_blocking(move || {
                    // Keep the permit until parsing actually ends, also if its awaiting future is dropped.
                    let _permit = permit;
                    serde_json::from_slice::<T>(&body).map_err(|error| {
                        RequestErrorKind::InvalidJson {
                            category: error.classify(),
                            line: error.line(),
                            column: error.column(),
                        }
                    })
                })
                .await
                .map_err(RequestErrorKind::Worker)?
        };
        let result = match tokio::time::timeout_at(deadline, request).await {
            Ok(Ok(_)) if Instant::now() >= deadline => Err(RequestErrorKind::Timeout),
            Ok(result) => result,
            Err(_) => Err(RequestErrorKind::Timeout),
        };
        result
            .map(|data| BoundedResponse {
                data,
                bytes_received,
            })
            .map_err(|kind| RequestError {
                kind,
                status,
                retry_after,
                bytes_received,
            })
    }
}

fn http_error(error: reqwest::Error) -> RequestErrorKind {
    if error.is_timeout() {
        RequestErrorKind::Timeout
    } else {
        RequestErrorKind::Http(error.without_url())
    }
}

fn parse_retry_after(headers: &header::HeaderMap) -> Result<Option<Duration>, RequestErrorKind> {
    let mut values = headers.get_all(header::RETRY_AFTER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    // Both delta-seconds and HTTP-date fit comfortably within this bound. Do not copy arbitrary
    // provider strings into errors or truncate an excessive delay into permission to retry sooner.
    if values.next().is_some() || value.as_bytes().len() > 128 {
        return Err(RequestErrorKind::InvalidRetryAfter);
    }
    let value = value
        .to_str()
        .map_err(|_| RequestErrorKind::InvalidRetryAfter)?
        .trim();
    let delay = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Duration::from_secs(
            value
                .parse()
                .map_err(|_| RequestErrorKind::InvalidRetryAfter)?,
        )
    } else {
        httpdate::parse_http_date(value)
            .map_err(|_| RequestErrorKind::InvalidRetryAfter)?
            .duration_since(SystemTime::now())
            .unwrap_or_default()
    };
    Ok(Some(delay))
}
