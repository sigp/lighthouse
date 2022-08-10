use crate::{types::Accept, Error, CONSENSUS_VERSION_HEADER};
use reqwest::{header::ACCEPT, RequestBuilder, Response, StatusCode};
use std::str::FromStr;
use types::ForkName;

/// Trait for converting a 404 error into an `Option<Response>`.
pub trait ResponseOptional {
    fn optional(self) -> Result<Option<Response>, Error>;
}

impl ResponseOptional for Result<Response, Error> {
    fn optional(self) -> Result<Option<Response>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Trait for extracting the fork name from the headers of a response.
pub trait ResponseForkName {
    #[allow(clippy::result_unit_err)]
    fn fork_name_from_header(&self) -> Result<Option<ForkName>, String>;
}

impl ResponseForkName for Response {
    fn fork_name_from_header(&self) -> Result<Option<ForkName>, String> {
        self.headers()
            .get(CONSENSUS_VERSION_HEADER)
            .map(|fork_name| {
                fork_name
                    .to_str()
                    .map_err(|e| e.to_string())
                    .and_then(ForkName::from_str)
            })
            .transpose()
    }
}

/// Trait for adding an "accept" header to a request builder.
pub trait RequestAccept {
    fn accept(self, accept: Accept) -> RequestBuilder;
}

impl RequestAccept for RequestBuilder {
    fn accept(self, accept: Accept) -> RequestBuilder {
        self.header(ACCEPT, accept.to_string())
    }
}
