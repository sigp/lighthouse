use crate::BoxFut;
use hyper::{Body, Response, StatusCode};
use std::error::Error as StdError;

#[derive(PartialEq, Debug, Clone)]
pub enum ApiError {
    MethodNotAllowed(String),
    ServerError(String),
    NotImplemented(String),
    BadRequest(String),
    NotFound(String),
    UnsupportedType(String),
    ImATeapot(String),       // Just in case.
    ProcessingError(String), // A 202 error, for when a block/attestation cannot be processed, but still transmitted.
}

pub type ApiResult = Result<Response<Body>, ApiError>;

impl ApiError {
    pub fn status_code(self) -> (StatusCode, String) {
        match self {
            ApiError::MethodNotAllowed(desc) => (StatusCode::METHOD_NOT_ALLOWED, desc),
            ApiError::ServerError(desc) => (StatusCode::INTERNAL_SERVER_ERROR, desc),
            ApiError::NotImplemented(desc) => (StatusCode::NOT_IMPLEMENTED, desc),
            ApiError::BadRequest(desc) => (StatusCode::BAD_REQUEST, desc),
            ApiError::NotFound(desc) => (StatusCode::NOT_FOUND, desc),
            ApiError::UnsupportedType(desc) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, desc),
            ApiError::ImATeapot(desc) => (StatusCode::IM_A_TEAPOT, desc),
            ApiError::ProcessingError(desc) => (StatusCode::ACCEPTED, desc),
        }
    }
}

impl Into<Response<Body>> for ApiError {
    fn into(self) -> Response<Body> {
        let status_code = self.status_code();
        Response::builder()
            .status(status_code.0)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(status_code.1))
            .expect("Response should always be created.")
    }
}

impl Into<BoxFut> for ApiError {
    fn into(self) -> BoxFut {
        Box::new(futures::future::err(self))
    }
}

impl From<store::Error> for ApiError {
    fn from(e: store::Error) -> ApiError {
        ApiError::ServerError(format!("Database error: {:?}", e))
    }
}

impl From<types::BeaconStateError> for ApiError {
    fn from(e: types::BeaconStateError) -> ApiError {
        ApiError::ServerError(format!("BeaconState error: {:?}", e))
    }
}

impl From<state_processing::per_slot_processing::Error> for ApiError {
    fn from(e: state_processing::per_slot_processing::Error) -> ApiError {
        ApiError::ServerError(format!("PerSlotProcessing error: {:?}", e))
    }
}

impl From<hyper::error::Error> for ApiError {
    fn from(e: hyper::error::Error) -> ApiError {
        ApiError::ServerError(format!("Networking error: {:?}", e))
    }
}

impl StdError for ApiError {
    fn cause(&self) -> Option<&dyn StdError> {
        None
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let status = self.clone().status_code();
        write!(f, "{:?}: {:?}", status.0, status.1)
    }
}
