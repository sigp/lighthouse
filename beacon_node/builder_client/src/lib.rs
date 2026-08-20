use eth2::types::{ContentType, ForkName};
use eth2::{CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
use reqwest::header::HeaderMap;
use std::str::FromStr;

pub mod builder_http_client;
pub mod builders;
pub mod error;
pub mod pre_gloas_builder_http_client;

pub use builder_http_client::BuilderHttpClient;
pub use builders::{BidRequestContext, Builders, DirectBid, SubmissionFailure};
pub use error::{Error, ok_or_error, success_or_error};
pub use pre_gloas_builder_http_client::PreGloasBuilderHttpClient;

/// Default user agent for HTTP requests.
pub const DEFAULT_USER_AGENT: &str = lighthouse_version::VERSION;

/// The value we set on the `ACCEPT` http header to indicate a preference for ssz response.
pub const PREFERENCE_ACCEPT_VALUE: &str = "application/octet-stream;q=1.0,application/json;q=0.9";
/// Only accept json responses.
pub const JSON_ACCEPT_VALUE: &str = "application/json";

/// Parse the `Eth-Consensus-Version` response header into a `ForkName`, if present.
pub fn fork_name_from_header(headers: &HeaderMap) -> Result<Option<ForkName>, String> {
    headers
        .get(CONSENSUS_VERSION_HEADER)
        .map(|fork_name| {
            fork_name
                .to_str()
                .map_err(|e| e.to_string())
                .and_then(ForkName::from_str)
        })
        .transpose()
}

/// Determine the `ContentType` of a response from its `Content-Type` header.
///
/// Defaults to JSON when the header is absent or unrecognized.
pub fn content_type_from_header(headers: &HeaderMap) -> ContentType {
    match headers
        .get(CONTENT_TYPE_HEADER)
        .and_then(|content_type| content_type.to_str().ok())
    {
        Some(SSZ_CONTENT_TYPE_HEADER) => ContentType::Ssz,
        _ => ContentType::Json,
    }
}
