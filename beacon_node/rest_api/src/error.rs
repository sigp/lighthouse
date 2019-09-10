use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::error::Error as StdError;

type Cause = Box<dyn StdErr + Send + Sync>;

pub struct ApiError {
    kind: ApiErrorKind,
    cause: Option<Cause>,
}

#[derive(PartialEq, Debug)]
pub enum ApiErrorKind {
    MethodNotAllowed(String),
    ServerError(String),
    NotImplemented(String),
    InvalidQueryParams(String),
    NotFound(String),
    ImATeapot(String), // Just in case.
}

pub type ApiResult = Result<Response<Body>, ApiError>;

impl Into<Response<Body>> for ApiError {
    fn into(self) -> Response<Body> {
        let status_code: (StatusCode, String) = match self {
            ApiError::MethodNotAllowed(desc) => (StatusCode::METHOD_NOT_ALLOWED, desc),
            ApiError::ServerError(desc) => (StatusCode::INTERNAL_SERVER_ERROR, desc),
            ApiError::NotImplemented(desc) => (StatusCode::NOT_IMPLEMENTED, desc),
            ApiError::InvalidQueryParams(desc) => (StatusCode::BAD_REQUEST, desc),
            ApiError::NotFound(desc) => (StatusCode::NOT_FOUND, desc),
            ApiError::ImATeapot(desc) => (StatusCode::IM_A_TEAPOT, desc),
        };
        Response::builder()
            .status(status_code.0)
            .header("content-type", "text/plain")
            .body(Body::from(status_code.1))
            .expect("Response should always be created.")
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

impl std::error::Error for ApiError {
    fn cause(&self) -> Option<&Error> {}
}
