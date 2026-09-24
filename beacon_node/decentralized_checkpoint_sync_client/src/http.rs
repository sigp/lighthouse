use crate::{
    LightClientData, LightClientDataSource, RequestLimits, SourceError, SourceErrorKind,
    SourceResponse, SourceResult, UpdateRange,
};
use eth2::{
    ForkVersionedResponse, SensitiveUrl,
    light_client::{
        BoundedResponse, LightClientHttpClient, RequestError, RequestErrorKind,
        RequestLimits as HttpRequestLimits,
    },
};
use std::{error::Error as StdError, io};
use types::{EthSpec, Hash256, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate};

/// Untrusted light-client data from one explicitly configured JSON REST provider.
///
/// Uses eth2's bounded client, preserving version metadata and measured bytes on success/failure.
/// Redirects and encoded bodies are rejected; requests and blocking JSON decoding share a bounded
/// lifetime. The caller supplies a Tokio runtime with time/I/O enabled. No store, verification,
/// retries, trusted network context or provider selection belongs to this adapter.
///
/// Use with [`crate::sync_verified_finalized_header`] for authenticated output and bounded retries.
/// Unknown/unsupported wire formats fail closed as `InvalidData`: the existing fork decoder reports
/// JSON failure, so this adapter does not invent a fork or guess one from an error message.
#[derive(Clone, Debug)]
pub struct HttpLightClientDataSource {
    client: LightClientHttpClient,
}

impl HttpLightClientDataSource {
    pub fn new(provider: SensitiveUrl) -> Result<Self, SourceError> {
        LightClientHttpClient::new(provider)
            .map(|client| Self { client })
            .map_err(source_error)
    }
}

impl<E: EthSpec> LightClientDataSource<E> for HttpLightClientDataSource {
    async fn get_bootstrap(
        &mut self,
        block_root: Hash256,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientBootstrap<E>>> {
        self.client
            .get_bootstrap::<E>(block_root, http_limits(limits)?)
            .await
            .map(|response| source_response(response, light_client_data))
            .map_err(source_error)
    }

    async fn get_updates(
        &mut self,
        range: UpdateRange,
        limits: RequestLimits,
    ) -> SourceResult<Vec<LightClientData<LightClientUpdate<E>>>> {
        self.client
            .get_updates::<E>(range.start_period(), range.count(), http_limits(limits)?)
            .await
            .map(|response| {
                source_response(response, |updates| {
                    updates.into_iter().map(light_client_data).collect()
                })
            })
            .map_err(source_error)
    }

    async fn get_finality_update(
        &mut self,
        limits: RequestLimits,
    ) -> SourceResult<LightClientData<LightClientFinalityUpdate<E>>> {
        self.client
            .get_finality_update::<E>(http_limits(limits)?)
            .await
            .map(|response| source_response(response, light_client_data))
            .map_err(source_error)
    }
}

fn http_limits(limits: RequestLimits) -> Result<HttpRequestLimits, SourceError> {
    HttpRequestLimits::new(limits.timeout(), limits.max_response_bytes()).map_err(source_error)
}

fn light_client_data<T>(response: ForkVersionedResponse<T>) -> LightClientData<T> {
    LightClientData {
        data_fork: response.version,
        data: response.data,
    }
}

fn source_response<T, U>(
    response: BoundedResponse<T>,
    map: impl FnOnce(T) -> U,
) -> SourceResponse<U> {
    SourceResponse {
        data: map(response.data),
        bytes_received: response.bytes_received,
    }
}

fn source_error(error: RequestError) -> SourceError {
    let transient = || SourceErrorKind::Transient {
        retry_after: error.retry_after,
    };
    // Kind takes precedence over HTTP status: a 503 cannot turn an oversized or malformed
    // response into a retryable availability problem. The actual status remains in the cause.
    let kind = match &error.kind {
        RequestErrorKind::Status => match error.status.map(|status| status.as_u16()) {
            Some(404) => SourceErrorKind::Unavailable,
            Some(408 | 429 | 500 | 502 | 503 | 504) => transient(),
            // Permissions, redirects, unsupported endpoints and unexpected statuses are terminal.
            _ => SourceErrorKind::Configuration,
        },
        RequestErrorKind::Timeout => transient(),
        RequestErrorKind::Http(error) if has_transient_io_cause(error) => transient(),
        RequestErrorKind::Http(_) => SourceErrorKind::Configuration,
        RequestErrorKind::InvalidJson { .. }
        | RequestErrorKind::InvalidHeaders
        | RequestErrorKind::InvalidRetryAfter => SourceErrorKind::InvalidData,
        RequestErrorKind::BodyTooLarge { limit } => {
            SourceErrorKind::ResponseTooLarge { limit: *limit }
        }
        RequestErrorKind::InvalidLimits
        | RequestErrorKind::InvalidRange
        | RequestErrorKind::InvalidUrl => SourceErrorKind::Configuration,
        RequestErrorKind::RuntimeUnavailable
        | RequestErrorKind::Worker(_)
        | RequestErrorKind::AllocationFailed => SourceErrorKind::LocalFailure,
    };
    SourceError {
        kind,
        bytes_received: error.bytes_received,
        source: Some(Box::new(error)),
    }
}

fn has_transient_io_cause(error: &(dyn StdError + 'static)) -> bool {
    let mut cause = Some(error);
    let mut transient = false;
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            match error.kind() {
                // In particular, TLS validation can surface as connect + InvalidData.
                io::ErrorKind::InvalidData
                | io::ErrorKind::InvalidInput
                | io::ErrorKind::PermissionDenied => return false,
                io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::Interrupted
                | io::ErrorKind::TimedOut
                | io::ErrorKind::WouldBlock => transient = true,
                _ => {}
            }
            // io::Error::source() skips its wrapped error itself. Inspect that error before
            // following its cause, otherwise nested transport or TLS failures can be lost.
            cause = error
                .get_ref()
                .map(|inner| inner as &(dyn StdError + 'static));
        } else {
            cause = error.source();
        }
    }
    // Do not infer transience from is_connect() or provider-controlled error strings.
    transient
}

#[cfg(test)]
mod tests;
