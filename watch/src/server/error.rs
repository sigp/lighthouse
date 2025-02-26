use crate::database::Error as DbError;
use axum::Error as AxumError;
use axum::{http::StatusCode, response::IntoResponse, Json};
use hyper::Error as HyperError;
use serde_json::json;
use std::io::Error as IoError;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    Axum(AxumError),
    Hyper(HyperError),
    Database(DbError),
    IoError(IoError),
    BadRequest,
    NotFound,
    Other(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "Bad Request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "Not Found"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
        };
        (status, Json(json!({ "error": error_message }))).into_response()
    }
}

impl From<HyperError> for Error {
    fn from(e: HyperError) -> Self {
        Error::Hyper(e)
    }
}

impl From<AxumError> for Error {
    fn from(e: AxumError) -> Self {
        Error::Axum(e)
    }
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        Error::Database(e)
    }
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IoError(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}
